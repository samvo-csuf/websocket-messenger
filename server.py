# server.py
import asyncio
import websockets
import json
import bcrypt
from cryptography.fernet import Fernet
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
from datetime import datetime, timedelta
import logging
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from config import DB_CONFIG, ENCRYPTION_KEY


# Print the exact file being executed
print(f"Running file: {os.path.abspath(__file__)}")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SecureChat')

# Encryption key (generate once and store securely)
cipher = Fernet(ENCRYPTION_KEY)

# Database connection
DB_CONFIG

# Store connected clients and their rate limits
clients = {}  # {websocket: {"username": str, "last_message": datetime, "message_count": int}}
RATE_LIMIT = 10  # messages per minute

# File transfer tracking
file_transfers = {}  # {file_id: {sender, recipient, key, iv, ...}}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

def encrypt_data(data):
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data).decode()

def encrypt_username(username):
    """Encrypt username in a deterministic way for consistent database lookups"""
    # Use a simple hash for lookups instead of encryption
    return hashlib.sha256(username.encode()).hexdigest()

# File transfer encryption 
def generate_file_key():
    """Generate a random encryption key for file transfer"""
    return os.urandom(32)  # 256-bit key

def encrypt_file_chunk(chunk, key, iv):
    """Encrypt a file chunk with AES-256-CBC"""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(chunk) + padder.finalize()
    logger.debug(f"Chunk size: {len(chunk)}, Padded size: {len(padded_data)}, Padded hex: {padded_data.hex()}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    logger.debug(f"Encrypted size: {len(encrypted_data)}")
    return encrypted_data

def decrypt_file_chunk(encrypted_chunk, key, iv):
    """Decrypt a file chunk with AES-256-CBC"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_chunk) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

async def handle_file_transfer(websocket, username, msg_data):
    """Handle file transfer messages"""
    msg_type = msg_data.get("type")
    
    if msg_type == "file_init":
        # Initiate file transfer
        file_id = msg_data.get("fileId")
        recipient_name = msg_data.get("recipient")
        
        # Generate encryption key and IV for this transfer
        key = generate_file_key()
        iv = os.urandom(16)  # 128-bit IV for AES
        
        # Store file transfer data
        file_transfers[file_id] = {
            "sender": username,
            "recipient": recipient_name,
            "file_name": msg_data.get("fileName"),
            "file_size": msg_data.get("fileSize"),
            "file_type": msg_data.get("fileType"),
            "key": key,
            "iv": iv,
            "chunks_received": 0,
            "total_chunks": 0
        }
        
        # Find recipient
        recipient_ws = None
        for ws, data in clients.items():
            if data["username"] == recipient_name:
                recipient_ws = ws
                break
        
        if recipient_ws:
            # Send file init to recipient with encryption info
            await recipient_ws.send(json.dumps({
                "type": "file_init",
                "fileId": file_id,
                "fileName": msg_data.get("fileName"),
                "fileSize": msg_data.get("fileSize"),
                "fileType": msg_data.get("fileType"),
                "sender": username,
                "key": base64.b64encode(key).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8')
            }))
        else:
            # Recipient not online
            await websocket.send(json.dumps({
                "type": "error",
                "message": f"User {recipient_name} is not online"
            }))
    
    elif msg_type == "file_chunk":
        # Handle file chunk
        file_id = msg_data.get("fileId")
        chunk_data = base64.b64decode(msg_data.get("data"))
        chunk_index = msg_data.get("chunkIndex")
        total_chunks = msg_data.get("totalChunks")
        
        if file_id in file_transfers:
            transfer = file_transfers[file_id]

            try:
            
            # Encrypt chunk
                encrypted_chunk = encrypt_file_chunk(
                    chunk_data, 
                    transfer["key"], 
                    transfer["iv"]
                )
                logger.info(f"Forwarding chunk {chunk_index}/{total_chunks} for {file_id}, encrypted size: {len(encrypted_chunk)}")
            except Exception as e:
                logger.error(f"Encryption failed for file {file_id}: {e}")
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": f"Encryption failed: {str(e)}"
                }))
                return
            
            # Find recipient
            recipient_ws = None
            for ws, data in clients.items():
                if data["username"] == transfer["recipient"]:
                    recipient_ws = ws
                    break
            
            if recipient_ws:
                # Forward encrypted chunk
                await recipient_ws.send(json.dumps({
                    "type": "file_chunk",
                    "fileId": file_id,
                    "data": base64.b64encode(encrypted_chunk).decode('utf-8'),
                    "chunkIndex": chunk_index,
                    "totalChunks": total_chunks,
                    "sender": username
                }))
                
                # Update progress
                transfer["chunks_received"] += 1
                transfer["total_chunks"] = total_chunks
                
                # If complete, clean up
                if transfer["chunks_received"] >= total_chunks:
                    await recipient_ws.send(json.dumps({
                        "type": "file_complete",
                        "fileId": file_id,
                        "fileName": transfer["file_name"],
                        "fileType": transfer["file_type"],
                        "sender": username
                    }))
                    # Keep transfer info for a while for security auditing
                    # Could schedule cleanup after some time
            else:
                # Recipient went offline
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": f"File transfer failed: recipient offline"
                }))

    elif msg_type == "file_accept":
            # Handle file accept message
            file_id = msg_data.get("fileId")
            sender_name = msg_data.get("recipient")  # This is actually the sender, since we're receiving from recipient

            # Find sender websocket
            sender_ws = None
            for ws, data in clients.items():
                if data["username"] == sender_name:
                    sender_ws = ws
                    break
        
            if sender_ws and file_id in file_transfers:
                # Notify sender they can start sending chunks
                await sender_ws.send(json.dumps({
                    "type": "file_accept",
                    "fileId": file_id,
                    "recipient": username
                }))
        
    elif msg_type == "file_complete":
            # File transfer complete notification
            file_id = msg_data.get("fileId")
            if file_id in file_transfers:
                # Clean up file transfer data after some time
                asyncio.create_task(delayed_cleanup(file_id))


async def delayed_cleanup(file_id, delay=60):
    """Clean up file transfer data after a delay"""
    await asyncio.sleep(delay)
    if file_id in file_transfers:
        del file_transfers[file_id]


async def signup(username, password):
    """Handle user signup data"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Check if username exists using consistent hash

                username_hash = encrypt_username(username)

                cur.execute(
                    "SELECT 1 FROM users WHERE username_hash = %s",
                    (username_hash,)
                )
                if cur.fetchone():
                    print(f"Username {username} already taken")
                    return {"type": "error", "message": "Username already taken"}
                
                # Hash password and store
                password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

                # Store both the username hash (for lookups) and the encrypted username (for display)
                encrypted_username = encrypt_data(username) # Keep this for display purposes if necessary

                cur.execute(
                    "INSERT INTO users (username_hash, username_encrypted, password_hash) VALUES (%s, %s, %s)",
                    (username_hash, encrypted_username, password_hash)
                )
                conn.commit()
                return {"type": "signup_success", "message": "Signup successful"}
    except Exception as e:
        print(f"Signup error: {e}")
        logger.error(f"Signup error: {e}")
        return {"type": "error", "message": f"Signup error: {str(e)}"}        

async def authenticate(websocket):
    """Handle user authentication"""
    try:
        # Receive authentication message
        auth_msg = await websocket.recv()
        print(f"Received auth message: {auth_msg}")
        auth_data = json.loads(auth_msg)

        auth_type = auth_data.get("type")
        username = auth_data.get("username")
        password = auth_data.get("password")

        if auth_type == "signup":
            result = await signup(username, password)
            await websocket.send(json.dumps(result))
            return None
        
        elif auth_type == "auth":
            # Check database for user
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    username_hash = encrypt_username(username)
                    
                    cur.execute(
                        "SELECT password_hash FROM users WHERE username_hash = %s",
                        (username_hash,)
                    )
                    user = cur.fetchone()

                    if user:

                        # Check password
                        stored_hash = user["password_hash"]
                        input_password = password.encode()

                        try:
                            password_match = bcrypt.checkpw(input_password, stored_hash.encode())

                            if password_match:
                                await websocket.send(json.dumps({"type": "auth_success", "message": "Authentication successful"}))
                                return username # Return username after successful authentication
                        except Exception as e:
                            print(f"Password check error: {e}")
                    else:
                        print(f"User {username} not found in database")
                    
                    # Authentication failed error
                    print(f"Authentication failed for {username}")
                    await websocket.send(json.dumps({"type": "error", "message": "Authentication failed"}))
                    return None
        else:
            print(f"Invalid auth type: {auth_type}")
            await websocket.send(json.dumps({"type": "error", "message": "Invalid authentication type"}))
            return None
        
    except Exception as e:
        print("Authentication error: {e}")
        logger.error(f"Authentication error: {e}")
        await websocket.send(json.dumps({"type": "error", "message": f"Authentication error: {str(e)}"}))
        return None
    
async def heartbeat(websocket):
    """Send periodic heartbeat to maintain connection"""
    while True:
        try:
            await websocket.ping()
            await asyncio.sleep(30)  # Ping every 30 seconds
        except websockets.ConnectionClosed:
            break

# Get list of online users
def get_online_users():
    return [client_data["username"] for client_data in clients.values()]

async def handle_client(websocket):
    """Handle individual client connections"""
    logger.info(f"New connection from {websocket.remote_address}")
    heartbeat_task = None
    username = None
    try:
        # Authentication
        logger.info("Starting authentication process")
        username = await authenticate(websocket)
        logger.info(f"Authentication result: username={username}")

        if not username:
            logger.info("Authentication failed or returned None, closing connection")
            print("Authentication failed, closing connection")
            return
            
        logger.info(f"User {username} authenticated successfully")
        print(f"User {username} authenticated successfully")
        
        clients[websocket] = {
            "username": username,
            "last_message": datetime.now() - timedelta(minutes=1),
            "message_count": 0
        }
        
        # Notify others of new connection
        join_msg = json.dumps({"type": "system", "message": f"{username} joined"})
        await broadcast(join_msg, websocket)
        
        # Start heartbeat
        heartbeat_task = asyncio.create_task(heartbeat(websocket))
        
        # Handle messages
        async for message in websocket:

            print(f"Message from {username}: {message}")
            msg_data = json.loads(message)
            now = datetime.now()
            client_data = clients[websocket]
            
            # Reset rate limit counter after a minute
            if now - client_data["last_message"] > timedelta(minutes=1):
                client_data["message_count"] = 0
                client_data["last_message"] = now
                
            if client_data["message_count"] >= RATE_LIMIT:
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "Rate limit exceeded"
                }))
                continue
                
            client_data["message_count"] += 1

            # Handle different message types
            if msg_data.get("type") == "get_users":
                # Send list of online users
                online_users = get_online_users()
                await websocket.send(json.dumps({"type": "user_list", "users": online_users}))

            elif msg_data.get("type") in ["file_init", "file_chunk", "file_accept", "file_complete"]:
                # Handle file transfer messages
                await handle_file_transfer(websocket, username, msg_data)

            elif msg_data.get("type") == "private":
                # Handle private message
                recipient_name = msg_data.get("recipient")
                message_content = msg_data.get("message")

                # Find recipient's websocket
                recipient_ws = None
                for ws, data in clients.items():
                    if data["username"] == recipient_name:
                        recipient_ws = ws
                        break

                if recipient_ws:
                    # Send to recipient
                    private_msg = json.dumps({"type": "message", "username": username, "message": message_content, "private": True, "recipient": recipient_name})
                    await recipient_ws.send(private_msg)

                    # Send copy to sender
                    await websocket.send(json.dumps({
                        "type": "message",
                        "username": username,
                        "message": message_content,
                        "timestamp": now.isoformat(),
                        "private": True,
                        "recipient": recipient_name
                    }))

                else:
                    # User offline or not found
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"User {recipient_name} is not online"
                    }))
            else:
                broadcast_msg = json.dumps({
                    "type": "message",
                    "username": username,
                    "message": msg_data["message"],
                    "timestamp": now.isoformat(),
                    "private": False
                })
                await broadcast(broadcast_msg, websocket)      

    except websockets.ConnectionClosed:
        pass
    finally:
        if websocket in clients:
            if username:  # Only try to notify if we have a username
                leave_msg = json.dumps({"type": "system", "message": f"{username} left"})
                # Remove the client before broadcasting to avoid the runtime error
                clients.pop(websocket)
                await broadcast(leave_msg, websocket)
        if heartbeat_task:
            heartbeat_task.cancel()

async def broadcast(message, sender_ws):
    """Broadcast message to all clients except sender"""
    # Create a copy of the clients keys to avoid modification during iteration
    client_connections = list(clients.keys())
    for ws in client_connections:
            try:
                await ws.send(message)
            except websockets.ConnectionClosed:
                pass

async def main():
    ssl_context = None  # Still in development 
    server = await websockets.serve(
        handle_client,
        "127.0.0.1",
        8765,
        ssl=ssl_context
    )
    logger.info("SecureChat server started on ws://localhost:8765")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())