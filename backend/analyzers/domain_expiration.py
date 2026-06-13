
import whois  # type: ignore[import-untyped]
from datetime import datetime, timezone
from typing import Optional
from dateutil import parser as dateutil_parser
from api.models import ModuleResult, SeverityLevel


def _parse_expiration_date(raw) -> Optional[datetime]:
    """Normalise la date d'expiration en datetime UTC-aware, quelle que soit la forme retournée par python-whois."""
    if isinstance(raw, list):
        # Prendre la première valeur non-None de la liste
        candidates = [x for x in raw if x is not None]
        if not candidates:
            return None
        raw = candidates[0]

    if raw is None:
        return None

    # python-whois retourne parfois une string pour certains TLDs
    if isinstance(raw, str):
        try:
            raw = dateutil_parser.parse(raw)
        except (ValueError, OverflowError):
            return None

    # Normaliser en UTC
    if raw.tzinfo is None:
        return raw.replace(tzinfo=timezone.utc)
    return raw.astimezone(timezone.utc)


def analyze_domain_expiration(domain: str) -> ModuleResult:
    """Vérifie la date d'expiration du domaine via WHOIS"""
    try:
        details = {}
        recommendations = []

        w = whois.whois(domain)
        expiration_date = _parse_expiration_date(w.expiration_date)

        if expiration_date is None:
            return ModuleResult(
                module_name="Domain Expiration",
                status="warning",
                severity=SeverityLevel.MEDIUM,
                score=50,
                details={"expiration_date": "non disponible"},
                recommendations=[
                    "Impossible de récupérer la date d'expiration via WHOIS. Vérifiez manuellement."
                ]
            )

        now = datetime.now(timezone.utc)
        days_remaining = (expiration_date - now).days

        details["expiration_date"] = expiration_date.strftime("%Y-%m-%d")
        details["days_remaining"] = days_remaining

        if w.registrar:
            details["registrar"] = w.registrar

        if days_remaining < 0:
            score = 0
            status = "error"
            severity = SeverityLevel.CRITICAL
            recommendations.append(
                f"Le domaine a expiré il y a {abs(days_remaining)} jour(s). Renouvellement immédiat requis."
            )
        elif days_remaining < 7:
            score = 0
            status = "error"
            severity = SeverityLevel.CRITICAL
            recommendations.append(
                f"Expiration imminente dans {days_remaining} jour(s). Renouveler immédiatement."
            )
        elif days_remaining < 30:
            score = 30
            status = "warning"
            severity = SeverityLevel.HIGH
            recommendations.append(
                f"Le domaine expire dans {days_remaining} jour(s). Renouvellement urgent recommandé."
            )
        elif days_remaining < 90:
            score = 60
            status = "warning"
            severity = SeverityLevel.MEDIUM
            recommendations.append(
                f"Le domaine expire dans {days_remaining} jour(s). Pensez à renouveler prochainement."
            )
        elif days_remaining < 180:
            score = 85
            status = "success"
            severity = SeverityLevel.LOW
            recommendations.append(
                f"Le domaine expire dans {days_remaining} jour(s). Anticipez le renouvellement."
            )
        else:
            score = 100
            status = "success"
            severity = SeverityLevel.LOW

        return ModuleResult(
            module_name="Domain Expiration",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations
        )

    except Exception as e:
        return ModuleResult(
            module_name="Domain Expiration",
            status="error",
            severity=SeverityLevel.HIGH,
            score=0,
            details={"error": str(e)},
            recommendations=[
                "Impossible d'interroger le WHOIS pour ce domaine."
            ]
        )
