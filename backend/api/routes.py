
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List
import uuid
from datetime import datetime
from api.models import (
    ScanRequest,
    ScanResponse,
    ScanResult,
    HistoryResponse,
    PlatformType,
    ModuleResult,
)

# Import des analyzers (à implémenter)
from analyzers.platform_detector import detect_platform
from analyzers.dns_analyzer import analyze_dns
from analyzers.ssl_analyzer import analyze_ssl


router = APIRouter(tags=["Audit"])

# Stockage temporaire en mémoire (sera remplacé par DB)
scans_storage = {}


@router.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        # Génération ID unique pour ce scan
        scan_id = str(uuid.uuid4())
                # background_tasks.add_task(run_all_analyzers, scan_id, request.domain)
        
        # Pour l'instant, retour d'un résultat mock

        # Analyser la plateforme
        platform = detect_platform(request.domain)

        # Analyser le DNS
        dns_result = analyze_dns(request.domain)

        # Analyser SSL/TLS
        ssl_result = analyze_ssl(request.domain)

        result = ScanResult(
            scan_id=scan_id,
            domain=request.domain,
            platform=platform,
            timestamp=datetime.now(),
            overall_score=(dns_result.score + ssl_result.score) // 2,
            modules=[dns_result,ssl_result],
            summary="Scan en cours...",
        )
        
        scans_storage[scan_id] = result
        
        return ScanResponse(
            success=True,
            scan_id=scan_id,
            result=result,
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors du scan: {str(e)}")


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_result(scan_id: str):

    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    
    return ScanResponse(
        success=True,
        scan_id=scan_id,
        result=scans_storage[scan_id],
    )


@router.get("/history", response_model=HistoryResponse)
async def get_scan_history(limit: int = 10):

    # TODO: Implémenter avec la DB
    return HistoryResponse(scans=[], total=0)


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    
    del scans_storage[scan_id]
    return {"success": True, "message": "Scan supprimé"}


@router.get("/platforms")
async def get_supported_platforms():
    return {
        "platforms": [platform.value for platform in PlatformType],
        "total": len(PlatformType),
    }
