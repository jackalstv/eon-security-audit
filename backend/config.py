from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "ÉON - Audit Sécurité TPE"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Base de données
    DATABASE_URL: str = "sqlite:///./eon.db"

    # API Keys (à configurer dans .env)
    HIBP_API_KEY: Optional[str] = None

    # CORS — toutes les origines possibles du frontend
    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "http://10.192.46.171:3000",
        "http://10.192.46.171:8000",
    ]

    # Limites
    MAX_SUBDOMAINS_CHECK: int = 50
    REQUEST_TIMEOUT: int = 10  # secondes

    class Config:
        env_file = ".env"
        case_sensitive = True


# Instance globale des settings
settings = Settings()