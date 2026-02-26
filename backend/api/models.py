from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import re
import dns.resolver


class PlatformType(str, Enum):
    SHOPIFY = "shopify"
    WIX = "wix"
    WORDPRESS = "wordpress"
    SQUARESPACE = "squarespace"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanRequest(BaseModel):
    domain: str = Field(..., description="Domaine à scanner (ex: example.com)")
    include_subdomains: bool = Field(default=True, description="Inclure scan des sous-domaines")

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        v = v.lower().strip()
        v = v.replace('https://', '').replace('http://', '').replace('www.', '')
        v = v.rstrip('/')

        # Vérifier le format
        pattern = r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError("Format de domaine invalide (ex: example.com)")

        # Vérifier que le domaine résout en DNS
        try:
            dns.resolver.resolve(v, 'A')
        except dns.resolver.NXDOMAIN:
            raise ValueError(f"Le domaine '{v}' n'existe pas")
        except dns.resolver.NoAnswer:
            try:
                dns.resolver.resolve(v, 'MX')
            except Exception:
                raise ValueError(f"Le domaine '{v}' ne résout pas")
        except Exception:
            raise ValueError(f"Impossible de résoudre le domaine '{v}'")

        return v


class ModuleResult(BaseModel):
    module_name: str
    status: str  # "success", "warning", "error", "info"
    severity: SeverityLevel
    score: int = Field(ge=0, le=100)
    details: Dict[str, Any]
    recommendations: List[str] = []


class ScanResult(BaseModel):
    scan_id: str
    domain: str
    platform: PlatformType
    timestamp: datetime
    overall_score: int = Field(ge=0, le=100)
    modules: List[ModuleResult]
    summary: str
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0


class RecommendationItem(BaseModel):
    priority: int = Field(ge=1, le=5)
    severity: SeverityLevel
    title: str
    description: str
    action: str
    estimated_time: str
    module: str


class ScanResponse(BaseModel):
    success: bool
    scan_id: str
    result: Optional[ScanResult] = None
    error: Optional[str] = None


class HistoryItem(BaseModel):
    scan_id: str
    domain: str
    timestamp: datetime
    overall_score: int
    platform: PlatformType


class HistoryResponse(BaseModel):
    scans: List[HistoryItem]
    total: int