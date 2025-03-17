import uvicorn
from secure_chat.main import create_app
import ssl
import socket

#Use socket to find local ip address, if it doesn't work then default to localhost ip
def get_local_ip():
    try:
        # Create a socket to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually create a connection
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return '127.0.0.1'  # Fallback to localhost if can't determine IP

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"Server will be available at: https://{local_ip}:8080")
    print("Make sure both computers are on the same network")
    
    # Create SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile='secure_chat/cert.pem',
        keyfile='secure_chat/key.pem'
    )
    
    # Configure and run uvicorn with SSL
    config = uvicorn.Config(
        "secure_chat.main:create_app",
        host=local_ip, 
        port=8080,  # Changed to match WebSocket port
        ssl_keyfile="secure_chat/key.pem",
        ssl_certfile="secure_chat/cert.pem",
        reload=False
    )
    
    server = uvicorn.Server(config)
    server.run()

