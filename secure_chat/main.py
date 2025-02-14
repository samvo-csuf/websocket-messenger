from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates  
from secure_chat.routes import router


def create_app() -> FastAPI:

#Instantiate the FastAPI app
    app = FastAPI()

    app.mount("/static", StaticFiles(directory="static"), name="static")
    templates = Jinja2Templates(directory="templates")
    app.include_router(router)


    return app






