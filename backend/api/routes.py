from fastapi import APIRouter, HTTPException, Depends  # type: ignore
from fastapi.responses import StreamingResponse  # type: ignore
from fastapi.concurrency import run_in_threadpool  # type: ignore
from sqlalchemy.orm import Session  # type: ignore
from io import BytesIO
import uuid
import json
import socket
from datetime import datetime

from api.models import (
    ScanRequest,
    ScanResponse,
    ScanResult,
    PlatformType,
    ModuleResult,
    SeverityLevel,
)
from database import get_db
from pdf_report import generate_pdf
from db_models import ScanRecord, ModuleRecord
from analyzers.platform_detector import detect_platform
from analyzers.dns_analyzer import analyze_dns
from analyzers.ssl_analyzer import analyze_ssl
from analyzers.security_headers_analyzer import analyze_security_headers
from analyzers.email_analyzer import analyze_email
from analyzers.domain_expiration import analyze_domain_expiration
from analyzers.subdomain_takeover_analyzer import detect_subdomain_takeover
from analyzers.osint_breaches import analyze_osint_breaches


router = APIRouter(tags=["Audit"])


def _result_to_db(scan_id: str, result: ScanResult) -> ScanRecord:
    record = ScanRecord(
        scan_id=scan_id,
        domain=result.domain,
        platform=result.platform.value,
        timestamp=result.timestamp,
        overall_score=result.overall_score,
        summary=result.summary,
        critical_issues=result.critical_issues,
        high_issues=result.high_issues,
        medium_issues=result.medium_issues,
        low_issues=result.low_issues,
        modules=[
            ModuleRecord(
                scan_id=scan_id,
                module_name=m.module_name,
                status=m.status,
                severity=m.severity.value,
                score=m.score,
                details=m.details,
                recommendations=m.recommendations,
            )
            for m in result.modules
        ],
    )
    return record


def _db_to_result(record: ScanRecord) -> ScanResult:
    return ScanResult(
        scan_id=record.scan_id,
        domain=record.domain,
        platform=PlatformType(record.platform),
        timestamp=record.timestamp,
        overall_score=record.overall_score,
        summary=record.summary,
        critical_issues=record.critical_issues,
        high_issues=record.high_issues,
        medium_issues=record.medium_issues,
        low_issues=record.low_issues,
        modules=[
            ModuleResult(
                module_name=m.module_name,
                status=m.status,
                severity=SeverityLevel(m.severity),
                score=m.score,
                details=m.details,
                recommendations=m.recommendations,
            )
            for m in record.modules
        ],
    )


@router.post("/scan", response_model=ScanResponse)
def start_scan(request: ScanRequest, db: Session = Depends(get_db)):
    # pas de async ici : les analyseurs sont synchrones et bloqueraient
    # le serveur pendant tout le scan (FastAPI met les def dans un threadpool)
    try:
        scan_id = str(uuid.uuid4())

        platform = detect_platform(request.domain)
        dns_result = analyze_dns(request.domain)
        ssl_result = analyze_ssl(request.domain)
        security_headers_result = analyze_security_headers(request.domain)
        email_result = analyze_email(request.domain)
        takeover_result = detect_subdomain_takeover(request.domain)
        expiration_result = analyze_domain_expiration(request.domain)
        osint_result = analyze_osint_breaches(request.domain)

        all_modules = [
            dns_result, ssl_result, security_headers_result,
            email_result, takeover_result, expiration_result, osint_result,
        ]
        overall_score = sum(m.score for m in all_modules) // len(all_modules)

        result = ScanResult(
            scan_id=scan_id,
            domain=request.domain,
            platform=platform,
            timestamp=datetime.now(),
            overall_score=overall_score,
            modules=all_modules,
            summary="Scan complété.",
            critical_issues=sum(1 for m in all_modules if m.severity == SeverityLevel.CRITICAL),
            high_issues=sum(1 for m in all_modules if m.severity == SeverityLevel.HIGH),
            medium_issues=sum(1 for m in all_modules if m.severity == SeverityLevel.MEDIUM),
            low_issues=sum(1 for m in all_modules if m.severity == SeverityLevel.LOW),
        )

        db.add(_result_to_db(scan_id, result))
        db.commit()

        return ScanResponse(success=True, scan_id=scan_id, result=result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors du scan: {str(e)}")


@router.post("/scan/stream")
async def start_scan_stream(request: ScanRequest, db: Session = Depends(get_db)):
    async def generate():
        try:
            await run_in_threadpool(socket.getaddrinfo, request.domain, None)
        except socket.gaierror:
            yield f"data: {json.dumps({'error': f'Domaine introuvable : {request.domain}'})}\n\n"
            return

        scan_id = str(uuid.uuid4())
        platform = await run_in_threadpool(detect_platform, request.domain)

        steps = [
            ("DNS Security", analyze_dns),
            ("SSL/TLS Security", analyze_ssl),
            ("Security Headers", analyze_security_headers),
            ("Email Security", analyze_email),
            ("Subdomain Takeover", detect_subdomain_takeover),
            ("Domain Expiration", analyze_domain_expiration),
            ("OSINT Breaches", analyze_osint_breaches),
        ]
        total = len(steps)
        modules = []

        for i, (name, fn) in enumerate(steps):
            yield f"data: {json.dumps({'step': name, 'progress': i, 'total': total})}\n\n"
            result = await run_in_threadpool(fn, request.domain)
            modules.append(result)

        overall_score = sum(m.score for m in modules) // len(modules)
        scan_result = ScanResult(
            scan_id=scan_id,
            domain=request.domain,
            platform=platform,
            timestamp=datetime.now(),
            overall_score=overall_score,
            modules=modules,
            summary="Scan complété.",
            critical_issues=sum(1 for m in modules if m.severity == SeverityLevel.CRITICAL),
            high_issues=sum(1 for m in modules if m.severity == SeverityLevel.HIGH),
            medium_issues=sum(1 for m in modules if m.severity == SeverityLevel.MEDIUM),
            low_issues=sum(1 for m in modules if m.severity == SeverityLevel.LOW),
        )
        db.add(_result_to_db(scan_id, scan_result))
        db.commit()

        result_dict = scan_result.model_dump(mode="json")
        yield f"data: {json.dumps({'done': True, 'scan_id': scan_id, 'result': result_dict})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/scan/{scan_id}/pdf")
async def download_pdf(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    result = _db_to_result(record)
    pdf_bytes = generate_pdf(result)
    filename = f"rapport-eon-{result.domain}-{result.timestamp.strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_result(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    return ScanResponse(success=True, scan_id=scan_id, result=_db_to_result(record))



@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    db.delete(record)
    db.commit()
    return {"success": True, "message": "Scan supprimé"}


@router.get("/platforms")
async def get_supported_platforms():
    return {
        "platforms": [platform.value for platform in PlatformType],
        "total": len(PlatformType),
    }
