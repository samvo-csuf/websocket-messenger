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


#Instantiate router
router = APIRouter()

#Instantiate and initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")

#Instantiate clients connected to the server
#Store the number of clients connected to the server in a set
clients_connected = set()

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
    return RedirectResponse(url="/chat", status_code=303)

#Render the chat room page
@router.get("/chat", response_class=HTMLResponse)
async def chatroom(request: Request):
    return templates.TemplateResponse("chatroom.html", {"request": request})

@router.post("/send_message")
@limiter.limit("5/minute") #Limit to 5 requests per minute
async def send_message(request: Request, message: str = Form(...)):
    if not message:
        raise HTTPException(status_code=400, detail="Invalid message")
    print(f"Message received: {message}")
    return {"message": message}

#Establishing websocket connection
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):

    #accept the websocket connection
    await websocket.accept()
    #add client to the set of connected clients
    clients_connected.add(websocket)

    #Add a message counter and timestamp for rate limiting
    message_counter = 0
    last_time_reset = time.time()

    try:
        while True:

            #Reset counter every minute
            current_time = time.time()
            if current_time - last_time_reset >= 60:
                message_counter = 0
                last_time_reset = current_time

            if message_counter >= 5:
                await websocket.send_text("Rate limit exceeded. Try again later.")
                await asyncio.sleep(60) #Wait for a minute before allowing more messages
                continue

            #Receive message from client
            data = await websocket.receive_text()
            message_counter += 1

            #Broadcast the message to all connected clients
            for client in clients_connected:
                await client.send_text(f"{data}")

    except WebSocketDisconnect: #Handle disconnection
        clients_connected.remove(websocket) #Remove disconnected client
        print(f"Client disconnected")


