import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    BACKBOARD_API_KEY: str = os.getenv("BACKBOARD_API_KEY", "")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./depguard.db")
    CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")


settings = Settings()
