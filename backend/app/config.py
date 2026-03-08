import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    BACKBOARD_API_KEY: str = os.getenv("BACKBOARD_API_KEY", "")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./depguard.db")
    CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:5174").split(",")
    AUTH0_DOMAIN: str = os.getenv("AUTH0_DOMAIN", "depguardai.ca.auth0.com")
    AUTH0_API_AUDIENCE: str = os.getenv("AUTH0_API_AUDIENCE", "")

settings = Settings()
