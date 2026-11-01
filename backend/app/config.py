import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    DEBUG = os.getenv("FLASK_ENV", "development") == "development"
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
        if origin.strip()
    ]

    # Banco SQLite; se não for definido, é criado em backend/instance/vault.db
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.getenv(
        "JWT_SECRET_KEY", "dev-jwt-secret-key-apenas-para-desenvolvimento-local"
    )
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("JWT_ACCESS_TOKEN_MINUTES", "30"))
    )
    JWT_ERROR_MESSAGE_KEY = "error"

    PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "600000"))

    # API Pwned Passwords do Have I Been Pwned (gratuita, sem chave)
    HIBP_API_URL = os.getenv("HIBP_API_URL", "https://api.pwnedpasswords.com")
    HIBP_TIMEOUT_SECONDS = float(os.getenv("HIBP_TIMEOUT_SECONDS", "5"))
    HIBP_USER_AGENT = os.getenv("HIBP_USER_AGENT", "AIPass")
