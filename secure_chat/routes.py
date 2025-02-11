from fastapi import APIRouter
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

#Initialize router
router = APIRouter()

#Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")


#Render the home page
@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@router.post("/login")
async def home(username: str = Form(...), password: str = Form(...)):
    if not username or not password:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return RedirectResponse(url="/chat", status_code=303)

#Render the home page
@router.get("/chat", response_class=HTMLResponse)
async def chatroom(request: Request):
    return templates.TemplateResponse("chatroom.html", {"request": request})

@router.post("/send_message")
async def send_message(message: str = Form(...)):
    if not message:
        raise HTTPException(status_code=400, detail="Invalid message")
    print(f"Message received: {message}")
    return {"message": message}

#Establishing websocket connection
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"Message text was: {data}")
    except WebSocketDisconnect: #Handle disconnection
        print(f"Client disconnected")

