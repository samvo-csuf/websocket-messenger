from fastapi import APIRouter
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from secure_chat.models import User, SessionLocal
from slowapi.util import get_remote_address 
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter
from secure_chat.limiter import limiter
import time
import asyncio
import json


#Instantiate router
router = APIRouter()

#Instantiate and initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")

#Instantiate clients connected to the server
#Store the number of clients connected to the server in a set
#clients_connected = set()

clients = {}

#Dependency to get the database session
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


#Render the signup page as home
@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@router.post("/signup")
async def signup(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(db_session)):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Username already exists"})
    user = User(username=username, password=password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return RedirectResponse(url="/login", status_code=303)

#Render the login page
@router.get("/login", response_class=HTMLResponse)
async def signup(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

#Handle login form submission
@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(db_session)):
    user = db.query(User).filter(User.username == username).first()
    if not user or user.password != password:
        return templates.TemplateResponse("index.html", {"request": request, "error": "Invalid credentials"})
    return RedirectResponse(url=f"/chat?username={username}", status_code=303)

#Render the chat room page
@router.get("/chat", response_class=HTMLResponse)
async def chatroom(request: Request):
    return templates.TemplateResponse("chatroom.html", {"request": request})

#@router.post("/send_message")
#@limiter.limit("5/minute") #Limit to 5 requests per minute
#async def send_message(request: Request, message: str = Form(...)):
#    if not message:
#        raise HTTPException(status_code=400, detail="Invalid message")
#    print(f"Message received: {message}")
#    return {"message": message}

#Establishing websocket connection
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, username: str = None):
    if not username:
        await websocket.accept()
        await websocket.close(code=1008, reason="Username required")
        return

    #accept the websocket connection
    await websocket.accept()
    clients[username] = websocket
    #add client to the set of connected clients
    #clients_connected.add(websocket)

    # Send initial user list
    await websocket.send_json({"type": "user_list", "users": list(clients.keys())})

    # Broadcast connection
    connect_message = {"type": "chat", "message": f"{username} connected", "to": None}
    await broadcast(connect_message, exclude=[username])

   # # Broadcast initial connection message only
   # connect_message = {"type": "chat", "message": f"{username}: \"connected to chatroom...\""}
   # for client in clients_connected.copy():
   #     try: 
   #         await client.send_json(connect_message)
   #     except Exception:
   #         pass



    #Add a message counter and timestamp for rate limiting
    #message_counter = 0
    #last_time_reset = time.time()

    #Heartbeat variables
    #last_message = time.time()
    last_heartbeat = time.time()
    HEARTBEAT_INTERVAL = 30 # Send heartbeat every 30 seconds
    #MESSAGE_TIMEOUT = 90 # Disconnect if no response after 90 seconds
    HEARTBEAT_TIMEOUT = 90
    #RECONNECT_DELAY = 3
    #was_disconnected = False

    async def send_heartbeat():
        nonlocal last_heartbeat
        while True:
            #try:
                #print(f"Sending heartbeat to {username} ({get_remote_address(websocket)}:{websocket.client.port}) at {time.time()}")
                await websocket.send_json({"type": "heartbeat"})
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if time.time() - last_heartbeat > HEARTBEAT_TIMEOUT:
                    await websocket.close(code=1003, reason="Heartbeat timeout")
                    break
           # except Exception as e:
                #print(f"Heartbeat failed for {username} ({get_remote_address(websocket)}:{websocket.client.port}): {e}")
                #break

            # Start heartbeat task
    heartbeat_operation = asyncio.create_task(send_heartbeat())

    #await asyncio.sleep(1)

    try:
        while True:

            data = await websocket.receive_text()
            #Reset counter every minute
            current_time = time.time()

            # Check for message timeout
            #if current_time - last_message > MESSAGE_TIMEOUT:
            #    print(f"Client {username} ({get_remote_address(websocket)}:{websocket.client.port}) timed out (no messages for {current_time - last_message:.1f}s)")
            #    # Broadcast reconnect attempt message
            #    reconnect_message = {"type": "chat", "message": f"{username}: \"Attempting to reconnect...\""}
            #    for client in clients_connected:
            #        try:
            #            await client.send_json(reconnect_message)
            #        except Exception:
            #            pass
            #    
            #    await websocket.close(code=1003, reason="No message timeout")
            #    was_disconnected = True
            #    break

            # Check for heartbeat timeout
            #if current_time - last_heartbeat > HEARTBEAT_TIMEOUT:
            #    print(f"Client {username} ({get_remote_address(websocket)}:{websocket.client.port}) timed out (no heartbeat for {current_time - last_heartbeat:.1f}s)")
            #    # Broadcast reconnect attempt message
            #    reconnect_message = {"type": "chat", "message": f"{username}: \"Attempting to reconnect...\""}
            #    for client in clients_connected:
            #        try:
            #            await client.send_json(reconnect_message)
            #        except Exception:
            #            pass
#
            #    await websocket.close(code=1003, reason="No heartbeat timeout")
            #    was_disconnected = True
            #    break

            #if current_time - last_time_reset >= 60:
            #    message_counter = 0
            #    last_time_reset = current_time
#
            #if message_counter >= 5:
            #    await websocket.send_json({"type": "error", "message": "Rate limit exceeded. Try again later."})
            #    await asyncio.sleep(60) #Wait for a minute before allowing more messages
            #    continue
#
            #try:
            #    
                #data = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
                #current_time = time.time()
                #time_since_last_message = current_time - last_message
                #time_since_last_heartbeat = current_time - last_heartbeat


            if data == "pong":
                    #print(f"Received pong from {username} ({get_remote_address(websocket)}:{websocket.client.port}) at {current_time}")
                    last_heartbeat = current_time
                    continue
            
            message = json.loads(data)

            if message["type"] == "get_users":
                await websocket.send_json({"type": "user_list", "users": list(clients.keys())})
                continue

            if message["type"] == "chat" and message["to"] in clients:
                full_message = {
                    "type": "chat",
                    "message": f"{username}: {message['message']}",
                    "to": message["to"]
                }
                await clients[message["to"]].send_json(full_message)
                await websocket.send_json(full_message)
                
                #last_heartbeat = current_time
               # message_counter += 1
               # message_data = {"type": "chat", "message": f"{username}: {data}"}

                #if was_disconnected:
                #    print(f"Reconnected client {username}, delaying message by {RECONNECT_DELAY} seconds")
                #    await asyncio.sleep(RECONNECT_DELAY)
                #    was_disconnected = False
#
                ##Broadcast the message to all connected clients
                #for client in clients_connected.copy(): # Use copy to avoid modification during iteration
                #    try:
                #        await client.send_json(message_data)
                #    except Exception:
                #        print(f"Removing client {get_remote_address(websocket)}:{websocket.client.port} due to send failure")
                #        clients_connected.remove(client)
                #print(f"Waiting for message from Client {username} ({get_remote_address(websocket)}:{websocket.client.port}), last heartbeat: {time_since_last_heartbeat:.1f}s ago")
                #last_message = current_time
                #last_heartbeat = current_time
#
            #except asyncio.TimeoutError:
            #    #print(f"Client {username} ({get_remote_address(websocket)}:{websocket.client.port}) timed out (no message for 90s)")
            #    continue
            
    except WebSocketDisconnect: #Handle disconnection
        pass
       # print(f"Client {username} ({get_remote_address(websocket)}:{websocket.client.port}) disconnected")
    
    finally:
        if username in clients:
            del clients[username]
        disconnect_message = {"type": "chat", "message": f"{username} disconnected", "to": None}
        await broadcast(disconnect_message)
        heartbeat_operation.cancel()

        #clients_connected.remove(websocket)
        ## Broadcast full disconnection only if not due to timeout (closed program)
        #if not was_disconnected:
        #    disconnect_message = {"type": "chat", "message": f"{username}: \"disconnected from chatroom...\""}
        #    for client in clients_connected.copy():
        #        try: 
        #            await client.send_json(disconnect_message)
        #        except Exception:
        #            pass 
#
        # Cleanup
       # print(f"Cleaning up connection for {username} ({get_remote_address(websocket)}:{websocket.client.port})")
       # heartbeat_operation.cancel()
       # if websocket.client_state == 1:
       #     try:
       #         await websocket.close()
       #     except Exception as e:
       #         print(f"Error during close: {e}")

async def broadcast(message, exclude=[]):
    for username, client in list(clients.items()):
        if username not in exclude:
            try:
                await client.send_json(message)
            except:
                pass