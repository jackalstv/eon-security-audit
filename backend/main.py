from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from database import Base, engine
import db_models  # noqa: F401 — enregistre les modèles ORM avant create_all

# Import des routes
from api.routes import router
from api.chat import router as chat_router

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Outil d'audit de sécurité automatisé pour TPE/PME",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,   # fix: True + origines explicites = OPTIONS 400
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)


@app.on_event("startup")
async def create_tables():
    Base.metadata.create_all(bind=engine)


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "docs": "/api/docs",
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# Inclusion des routes API
app.include_router(router, prefix="/api/v1")
app.include_router(chat_router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )