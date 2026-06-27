import json

import anthropic
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from db_models import ScanRecord

router = APIRouter(tags=["Chat"])


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []


def _system_prompt(scan: ScanRecord) -> str:
    mods = ""
    for m in scan.modules:
        icon = "✓" if m.score >= 75 else "⚠" if m.score >= 40 else "✗"
        mods += f"\n  {icon} {m.module_name} : {m.score}/100 ({m.severity})"
        for rec in (m.recommendations or []):
            mods += f"\n      → {rec}"

    return (
        "Tu es un expert en cybersécurité intégré à l'outil ÉON. "
        "Tu analyses les résultats d'audit de sécurité et tu guides l'utilisateur.\n\n"
        f"Résultats du scan :\n"
        f"  Domaine : {scan.domain}\n"
        f"  Score global : {scan.overall_score}/100\n"
        f"  Critiques : {scan.critical_issues} · Élevés : {scan.high_issues} · "
        f"Moyens : {scan.medium_issues} · Faibles : {scan.low_issues}\n"
        f"  Modules :{mods}\n\n"
        "Règles :\n"
        "- Réponds uniquement en français\n"
        "- Sois concis, pratique et pédagogique\n"
        "- Priorise les actions critiques et élevées\n"
        "- Cite les modules concernés quand c'est pertinent\n"
        "- Ne réponds pas aux sujets sans rapport avec la cybersécurité de ce domaine"
    )


@router.post("/chat/{scan_id}")
async def chat(scan_id: str, body: ChatRequest, db: Session = Depends(get_db)):
    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(503, detail="ANTHROPIC_API_KEY non configurée sur le serveur")

    scan = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(404, detail="Scan introuvable")

    client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    messages = [{"role": m.role, "content": m.content} for m in body.history]
    messages.append({"role": "user", "content": body.message})

    async def stream():
        try:
            async with client.messages.stream(
                model="claude-haiku-4-5-20251001",
                max_tokens=1024,
                system=_system_prompt(scan),
                messages=messages,
            ) as s:
                async for chunk in s.text_stream:
                    yield f"data: {json.dumps({'text': chunk})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
