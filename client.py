# client.py - Modified with better debugging
import sys
import asyncio
import websockets
import json
from datetime import datetime

class SecureChatClient:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.websocket = None
        self.url = "ws://127.0.0.1:8765"
        
    async def connect(self):
        """Connect to the server and authenticate"""
        try:
            print(f"Connecting to {self.url}...")
            self.websocket = await websockets.connect(self.url)
            print("Connected! Authenticating...")
            
            auth_msg = json.dumps({
                "type": "auth",
                "username": self.username,
                "password": self.password
            })
            await self.websocket.send(auth_msg)
            print("Authentication message sent, waiting for response...")
            
            response = await self.websocket.recv()  # Wait for server response
            print(f"Received response: {response}")
            
            data = json.loads(response)
            if data.get("type") == "error":
                print(f"[ERROR] {data['message']}")
                return False
                
            print(f"Successfully authenticated as {self.username}")
            asyncio.create_task(self.handle_messages())
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    async def handle_messages(self):
        """Handle incoming messages"""
        print("Starting message handler...")
        try:
            async for message in self.websocket:
                print(f"Raw message received: {message}")
                data = json.loads(message)
                if data["type"] == "message":
                    print(f"[{data['timestamp']}] {data['username']}: {data['message']}")
                elif data["type"] == "system":
                    print(f"[SYSTEM] {data['message']}")
                elif data["type"] == "error":
                    print(f"[ERROR] {data['message']}")
        except websockets.ConnectionClosed as e:
            print(f"Connection closed: {e}")
            await self.reconnect()
        except Exception as e:
            print(f"Error in message handler: {e}")

    async def send_message(self, message):
        """Send a message to the server"""
        if self.websocket:
            try:
                msg = json.dumps({"message": message})
                print(f"Sending message: {message}")
                await self.websocket.send(msg)
            except websockets.exceptions.ConnectionClosed:
                print("Cannot send message: WebSocket is closed")
        else:
            print("Cannot send message: WebSocket is not connected")

    async def reconnect(self):
        """Attempt to reconnect on connection loss"""
        attempt = 0
        max_attempts = 5
        while attempt < max_attempts:
            print(f"Attempting to reconnect ({attempt + 1}/{max_attempts})...")
            if await self.connect():
                return
            await asyncio.sleep(2)  # Reduced delay for testing
            attempt += 1
        print("Max reconnection attempts reached. Giving up.")

async def main(username, password):

    print("Starting SecureChat client...")
    # Create a client for demo (you can add more clients if desired)
    client = SecureChatClient(username, password)
    
    # Connect the clients and ensure success
    print("Connecting client...")
    success = await client.connect()

    if not success:
        print("Client failed to connect. Exiting.")
        return
    
    print("Chat session started. Type your messages below (or 'quit' to exit):")
    
    # Run message sending and receiving concurrently
    loop = asyncio.get_event_loop()
    while True:
        # Get user input asynchronously
        message = await loop.run_in_executor(None, input, f"{username}> ")
        if message.lower() == "quit":
            print("Exiting chat client...")
            break
        await client.send_message(message)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <username> <password>")
        sys.exit(1)
    username, password = sys.argv[1], sys.argv[2]
    
    asyncio.run(main(username, password))