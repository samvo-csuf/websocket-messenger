from fastapi import FastAPI, Request
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates  
from secure_chat.routes import router
from fastapi.responses import JSONResponse
#from secure_chat.limiter import limiter 

def create_app() -> FastAPI:
#Instantiate the FastAPI app
    app = FastAPI()

    #app.state.limiter = limiter
    #app.add_middleware(SlowAPIMiddleware)
    app.mount("/static", StaticFiles(directory="static"), name="static")
    templates = Jinja2Templates(directory="templates")
    app.include_router(router)

   # @app.exception_handler(RateLimitExceeded)
   # async def rate_limiter_exceeded_handler(request: Request, exc: RateLimitExceeded):
   #     return JSONResponse(status_code=429,
   #     content={"detail": "Rate limit exceeded. Try again later."},
   #     )
   # 
    return app






