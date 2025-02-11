import uvicorn
from secure_chat.main import create_app

app = create_app()


if __name__ == "__main__":
    uvicorn.run("secure_chat.main:create_app", host="127.0.0.1", port=8000, reload=True)
