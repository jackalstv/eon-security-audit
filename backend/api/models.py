
from pydantic import BaseModel, Field, HttpUrl, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


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
    
    @validator('domain')
    def validate_domain(cls, v):
        v = v.lower().strip()
        # Retirer https:// ou http:// si présent
        v = v.replace('https://', '').replace('http://', '').replace('www.', '')
        # Retirer le trailing slash
        v = v.rstrip('/')
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
    estimated_time: str  # "5 min", "1 heure", etc.
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
