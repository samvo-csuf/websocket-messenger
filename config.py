# config.py
import os
from dotenv import load_dotenv

# load environment variables from .env file
load_dotenv()

# Database configuration
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT")
}

# Encryption key (base64-encoded 32-byte key for Fernet)
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY").encode() if os.getenv("ENCRYPTION_KEY") else None