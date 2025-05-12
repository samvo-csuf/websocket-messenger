# server.py
import asyncio
import websockets
import json
import bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
from datetime import datetime, timedelta
import logging
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import ssl

from config import DB_CONFIG, ENCRYPTION_KEY


# Configure logging for server operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SecureChat')

# Print the exact file being executed
print(f"Running file: {os.path.abspath(__file__)}")

# Chat logging system
class ChatLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        self.loggers = {} # {session_id: logger}

    def get_session_id(self, username, chat_target):
        """Generate a unique session ID based on username and target"""
        return hashlib.sha256(f"{username}:{chat_target}".encode()).hexdigest()

    def get_logger(self, username, chat_target):
        """Get or create a logger for a specific chat session"""
        session_id = self.get_session_id(username, chat_target)
        if session_id not in self.loggers:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(self.log_dir, f"chat_{session_id}_{timestamp}.txt")
            logger = logging.getLogger(f"chat_{session_id}")    
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            self.loggers[session_id] = logger
        return self.loggers[session_id]
    
    def log_message(self, username, chat_target, message, sender):
        """Log a message to the appropriate chat session"""
        logger = self.get_logger(username, chat_target)
        logger.info(f"[{sender}] {message}")

# Initialize chat logger
chat_logger = ChatLogger()

# Encryption key (generate once and store securely)
#cipher = Fernet(ENCRYPTION_KEY)

# Database connection
#DB_CONFIG

# Store connected clients and their rate limits
clients = {}  # {websocket: {"username": str, "last_message": datetime, "message_count": int, "public key": RSAPublicKey}}
RATE_LIMIT = 10  # messages per minute

# File transfer tracking
file_transfers = {}  # {file_id: {sender, recipient, key, iv, ...}}

# Encryption keys
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
server_public_key = server_private_key.public_key()

MAX_LOGIN_ATTEMPTS = 5  # Max login attempts before lockout
LOCKOUT_DURATION = timedelta(minutes=15)  # Duration of lockout

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

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

# Generate message key 
def generate_message_key():
    return os.urandom(32) # 256-bit AES key

def encrypt_message(message, key, iv):
    """Encrypt messages with AES-256-CBC"""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()
   
def decrypt_file_chunk(encrypted_data, key, iv):
    """Decrypt message with AES-256-CBC"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize().decode()

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

async def check_login_attempts(username, remote_address):
    """Check if user is locked out due to too many failed login attempts"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                username_hash = encrypt_username(username)
                cur.execute(
                    """
                    SELECT failed_attempts, last_failed_attempt, locked_until
                    FROM login_attempts
                    WHERE username_hash = %s
                    """,
                    (username_hash,)
                )
                result = cur.fetchone()
                logger.debug(f"Checked login attempts for {username} from {remote_address}: {result}")
                if result:
                    failed_attempts = result["failed_attempts"]
                    locked_until = result["locked_until"]
                    now = datetime.now()

                    if locked_until and now < locked_until:
                        remaining_time = (locked_until - now).total_seconds() / 60
                        return {
                            "locked": True,
                            "message": f"Account locked due to too many failed attempts. Try again in {int(remaining_time)} minutes."
                        }
                    
                    return {"locked": False, "failed_attempts": failed_attempts}
                
                return {"locked": False, "failed_attempts": 0}
    except Exception as e:
        logger.error(f"Error checking login attempts for {username} from {remote_address}: {e}")
        return {"locked": True, "message": "Authentication temporarily disabled due to server error"}
    

async def increment_failed_attempts(username, remote_address):
    """Increment failed login attempts and lock account if necessary"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                username_hash = encrypt_username(username)
                now = datetime.now()

                # First, get current attempts
                cur.execute(
                    "SELECT failed_attempts FROM login_attempts WHERE username_hash = %s",
                    (username_hash,)
                )
                result = cur.fetchone()

                if result:
                    # Record exists, update it
                    new_attempts = result["failed_attempts"] + 1
                    locked_until = None
                    if new_attempts >= MAX_LOGIN_ATTEMPTS:
                        locked_until = now + LOCKOUT_DURATION

                    cur.execute(
                        """
                        UPDATE login_attempts
                        SET failed_attempts = %s,
                            last_failed_attempt = %s,
                            locked_until = %s
                        WHERE username_hash = %s
                        """,
                        (new_attempts, now, locked_until, username_hash)
                    )
                else:
                    # Create new record
                    cur.execute(
                        """
                        INSERT INTO login_attempts
                        (username_hash, failed_attempts, last_failed_attempt, locked_until)
                        VALUES (%s, 1, %s, NULL)
                        """,
                        (username_hash, now)
                    )
                    new_attempts = 1

                conn.commit()
                
                is_locked = new_attempts >= MAX_LOGIN_ATTEMPTS
                logger.info(f"Incremented failed attempt for {username} from {remote_address}. Count: {new_attempts} Locked: {is_locked}")
                return is_locked
            
    except Exception as e:
        logger.error(f"Error incrementing failed attempts for {username} from {remote_address}: {e}")
        return True # Assume locked on error for safety


async def reset_failed_attempts(username, remote_address):
    """Reset failed login attempts on successful login"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                username_hash = encrypt_username(username)
                cur.execute(
                    """
                    UPDATE login_attempts
                    SET failed_attempts = 0, last_failed_attempt = NULL, locked_until = NULL
                    WHERE username_hash = %s
                    """,
                    (username_hash,)
                )
                if cur.rowcount == 0:
                    logger.debug(f"No login attempts found for {username_hash} from {remote_address}, creating one")
                    cur.execute(
                        """
                        INSERT INTO login_attempts (username_hash, failed_attempts, last_failed_attempt, locked_until)
                        VALUES (%s, 0, NULL, NULL)
                        """,
                        (username_hash,)
                    )
                conn.commit()
                logger.info(f"Reset failed attempts for {username} from {remote_address}")
    except Exception as e:
        logger.error(f"Error resetting failed attempts for {username} from {remote_address}: {e}")

async def cleanup_login_attempts():
    """Periodically clean up login attempts for non-existent users and expired lockouts"""
    while True:
        try:
            logger.info("Starting scheduled cleanup of login_attempts table")
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    # Delete records for non-existent users
                    cur.execute(
                        """
                        DELETE FROM login_attempts la
                        WHERE NOT EXISTS (
                            SELECT 1 FROM users u WHERE u.username_hash = la.username_hash
                        )
                        AND (la.last_failed_attempt IS NULL OR la.last_failed_attempt < %s)
                        """,
                        (datetime.now() - timedelta(hours=72),)  # Keep records for 72 hours
                    )

                    non_existent_removed = cur.rowcount
                    # Reset failed attempts for lockouts
                    cur.execute(
                        """
                        UPDATE login_attempts
                        SET failed_attempts = 0, locked_until = NULL
                        WHERE locked_until IS NOT NULL AND locked_until < %s
                        """,
                        (datetime.now(),)
                    )
                    lockouts_reset = cur.rowcount

                    conn.commit()
                    logger.info(f"Cleanup completed: removed {non_existent_removed} entries for non-existent users, reset: {lockouts_reset} expired lockouts")

                await asyncio.sleep(259200)  # Run every 72 hours (3 days)
        except Exception as e:
            logger.error(f"Error during cleanup of login_attempts: {e}")
            await asyncio.sleep(3600)  # Wait 1 hour before retrying on error
            

async def signup(username, password):
    """Handle user signup data"""
    try:
        # Basic valildation
        if not username or not password:
            logger.warning("Attempted signup with empty username or password")
            return {"type": "error", "message": "Username and password are required"}
        
        if len(password) < 8:
            logger.warning(f"Attempted signup with short password for username {username}")
            return {"type": "error", "message": "Password must be at least 8 characters"}
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Check if username exists using consistent hash

                username_hash = encrypt_username(username)

                cur.execute(
                    "SELECT 1 FROM users WHERE username_hash = %s",
                    (username_hash,)
                )
                if cur.fetchone():
                    logger.warning(f"Username {username} already taken")
                    return {"type": "error", "message": "Username already taken"}
                try:

                    # Hash password and store
                    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')

                    if not password_hash or len(password_hash) < 10:
                        raise ValueError("Password hashing failed - produced empty or invalid hash")
                    
                    if not bcrypt.checkpw(password.encode(), password_hash.encode()):
                        raise ValueError("Password verification failed after hashing failed")
                    
                    logger.info(f"Successfully created hash for new user {username}")
                

                except Exception as e:
                    logger.error(f"Password hashing error: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    return {"type": "error", "message": "Error processing password"}
                
                logger.debug(f"Inserting new user with hash length: {len(password_hash)}")

                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username_hash VARCHAR(64) PRIMARY KEY,
                        password_hash TEXT NOT NULL
                )
                """)

                cur.execute(
                    "INSERT INTO users (username_hash, password_hash) VALUES (%s, %s)",
                    (username_hash, password_hash)
                )
                conn.commit()
                try:
                    # Verify if the user was created properly
                    cur.execute(
                        "SELECT * FROM users WHERE username_hash = %s",
                        (username_hash,)
                    )

                    result = cur.fetchone()
                    if not result:
                        logger.error(f"User creation verification failed - user not found: {username}")
                        return {"type": "error", "message": "User creation failed - could not find user"}
                    

                    if 'password_hash' not in result:
                        logger.error(f"User creation verification failed - no password_hash column: {username}")
                        return {"type": "error", "message": "User creation failed - database schema issue"}

                    if not result["password_hash"]:
                        logger.info(f"User creation verification failed - empty password_hash: {username}")
                        return {"type": "error", "message": "User creation failed - empty password hash"}
                    
                except Exception as e:
                    logger.error(f"User verification failed: str{e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    return {"type": "error", "message": f"User creation verification error: str{e}"}
                
                logger.info(f"New user created and verified: {username}")
                return {"type": "signup_success", "message": "User created successfully"}
    except Exception as e:
        logger.error(f"Signup error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {"type": "error", "message": f"Signup error: {str(e)}"}        

async def authenticate(websocket):
    """Handle user authentication"""
    remote_address = websocket.remote_address
    try:
        # Receive authentication message
        auth_msg = await websocket.recv()
        auth_data = json.loads(auth_msg)

        auth_type = auth_data.get("type")
        username = auth_data.get("username")
        password = auth_data.get("password")
        public_key_pem = auth_data.get("public_key") # Client's RSA public key

        if not public_key_pem:
            logger.warning(f"No public key provided by client {username} from {remote_address}")
            await websocket.send(json.dumps({
                "type": "error",
                "message": "Missing public key during authentication"
            }))
            return None, None


        if auth_type == "signup":
            result = await signup(username, password)
            await websocket.send(json.dumps(result))
            return None, None
        
        elif auth_type == "auth":
            # Check for brute-force attempts
            login_check = await check_login_attempts(username, remote_address)
            if login_check["locked"]:
                logger.warning(f" Locked login attempt for {username} from {remote_address}")
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": login_check["message"]
                }))
                return None, None

            # Check database for user
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    username_hash = encrypt_username(username)
                    
                    cur.execute(
                        "SELECT password_hash FROM users WHERE username_hash = %s",
                        (username_hash,)
                    )
                    user = cur.fetchone()
                    logger.debug(f"Authentication for {username}: Found user record: {user is not None}")

                    if user:
                        logger.debug(f"Password has exists: {user['password_hash'] is not None}")

                    if user and user["password_hash"] and user["password_hash"].strip(): # Make sure user exists and has a password hash

                        # Check password
                        stored_hash = user["password_hash"]

                        try:

                            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                                # Reset failed attempts on successful login
                                await reset_failed_attempts(username, remote_address)

                                # Load client's public key
                                public_key = serialization.load_pem_public_key(
                                    public_key_pem.encode(),
                                    backend=default_backend()
                                )
                                # Send server's public key
                                server_public_key_pem = server_public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                ).decode()

                                await websocket.send(json.dumps({"type": "auth_success", "message": "Authentication successful", "server_public_key": server_public_key_pem}))
                                return username, public_key # Return username after successful authentication
                            else:
                                logger.warning(f"Password mismatch for user {username} from {remote_address}")
                            
                        except Exception as e:
                            logger.error(f"Password check error for user {username} from {remote_address}: {e}")
                            import traceback
                            logger.error(traceback.format_exc())
                    else:
                        if user:
                            logger.warning(f"User {username} found but has invalid password hash: '{user['password_hash']}'")
                        else:
                            logger.warning(f"User {username} not found in database, attempted from {remote_address}")
                    
                    # Authentication failed error
                    is_locked = await increment_failed_attempts(username, remote_address)
                    error_message = "Authentication failed"
                    if is_locked:
                        error_message = f"Account locked due to too many failed attempts. Try again in {LOCKOUT_DURATION.total_seconds() / 60} minutes."
                    logger.warning(f"Authentication failed for {username} from {remote_address}. Locked: {is_locked}")
                    await websocket.send(json.dumps({"type": "error", "message": error_message}))
                    return None, None
        else:
            logger.warning(f"Invalid auth type {auth_type} from {remote_address}")
            await websocket.send(json.dumps({"type": "error", "message": "Invalid authentication type"}))
            return None, None
        
    except Exception as e:
        logger.error(f"Authentication error from {remote_address}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        await websocket.send(json.dumps({"type": "error", "message": f"Authentication error: {str(e)}"}))
        return None, None
    
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
        auth_result = await authenticate(websocket)
        username, public_key = auth_result if auth_result else (None, None)
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
            "message_count": 0,
            "public_key": public_key
        }
        
        # Notify others of new connection
        join_msg = json.dumps({"type": "system", "message": f"{username} joined"})
        await broadcast(join_msg, websocket)

        chat_logger.log_message(username, "global", f"{username} joined", "SYSTEM")
        
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
                recipient_public_key = None
                for ws, data in clients.items():
                    if data["username"] == recipient_name:
                        recipient_ws = ws
                        recipient_public_key = data["public_key"]
                        break

                if recipient_ws:
                    message_key = generate_message_key()
                    message_iv = os.urandom(16)  # 128-bit IV for AES
                    encrypted_message = encrypt_message(
                        message_content, 
                        message_key, 
                        message_iv
                    )
                    encrypted_key = recipient_public_key.encrypt(
                        message_key,
                        asymmetric.padding.OAEP(
                            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    # Send to recipient
                    private_msg = json.dumps({
                        "type": "message", 
                        "username": username, 
                        "message": base64.b64encode(encrypted_message).decode('utf-8'), 
                        "key": base64.b64encode(encrypted_key).decode('utf-8'), 
                        "iv": base64.b64encode(message_iv).decode('utf-8'), 
                        "private": True, 
                        "recipient": recipient_name
                        })
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
                    chat_logger.log_message(username, recipient_name,
                    message_content, username)
                    chat_logger.log_message(recipient_name, username,
                    message_content, username)

                else:
                    # User offline or not found
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"User {recipient_name} is not online"
                    }))
            else:
                message_key = generate_message_key()
                message_iv = os.urandom(16)  # 128-bit IV for AES
                encrypted_message = encrypt_message(
                    msg_data["message"], 
                    message_key, 
                    message_iv
                )
                broadcast_msg = json.dumps({
                    "type": "message",
                    "username": username,
                    "message": base64.b64encode(encrypted_message).decode('utf-8'),
                    "key": base64.b64encode(message_key).decode('utf-8'),
                    "iv": base64.b64encode(message_iv).decode('utf-8'),
                    "timestamp": now.isoformat(),
                    "private": False
                })
                await broadcast(broadcast_msg, websocket)
                chat_logger.log_message(username, "global", msg_data["message"], username)

    except websockets.ConnectionClosed:
        pass
    finally:
        if websocket in clients:
            if username:  # Only try to notify if we have a username
                leave_msg = json.dumps({"type": "system", "message": f"{username} left"})
                # Remove the client before broadcasting to avoid the runtime error
                clients.pop(websocket)
                await broadcast(leave_msg, websocket)
                chat_logger.log_message(username, "global", f"{username} left", "SYSTEM")
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

async def ensure_db_schema():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        username_hash VARCHAR(64) PRIMARY KEY,
                        failed_attempts INTEGER DEFAULT 0,
                        last_failed_attempt TIMESTAMP,
                        locked_until TIMESTAMP
                    )
                    """)
                conn.commit()
                logger.info("Verified or created login_attempts table")
    except Exception as e:
        logger.error(f"Failed to ensure login_attempts table: {e}")
        raise RuntimeError("Database schema initialization failed")


async def main():
    await ensure_db_schema()
    # Get the directory of where server.py is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # Still in development 
    ssl_context.load_cert_chain(
        certfile=os.path.join(script_dir, "cert.pem"),
        keyfile=os.path.join(script_dir, "key.pem")
    )

    # Start the cleanup task
    cleanup_task = asyncio.create_task(cleanup_login_attempts())

    server = await websockets.serve(
        handle_client,
        "localhost",
        8765,
        ssl=ssl_context
    )
    logger.info("SecureChat server started on wss://localhost:8765")

    try:
        await server.wait_closed()
    finally:
        # Make sure to cancel the cleanup task when the server stops
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    asyncio.run(main())