import http.server
import ssl 
import os


# Directory where html files are stored
script_dir = os.path.dirname(os.path.abspath(__file__))

# Set up the server
server_address = ('', 8443) # Port 8443 for HTTPS
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Configure SSL with the same certificate and key
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(
    certfile=os.path.join(script_dir, 'cert.pem'), 
    keyfile=os.path.join(script_dir, 'key.pem')
    ) 

# Wrap the HTTP server with SSL
httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

# Start the server 
print(f"Serving HTTPS on https://localhost:8443")
httpd.serve_forever()

