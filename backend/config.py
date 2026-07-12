from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ÉON - Audit Sécurité TPE"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Base de données
    DATABASE_URL: str = "sqlite:///./eon.db"

    # API Keys (à configurer dans .env)
    HIBP_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None

    # CORS — toutes les origines possibles du frontend
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "http://10.192.46.171:3000",
        "http://10.192.46.171:8000",
        "http://132.145.74.215",
        "http://132.145.74.215:8000",
    ]

    REQUEST_TIMEOUT: int = 10

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)


settings = Settings()