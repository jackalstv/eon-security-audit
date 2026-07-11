
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
                    "Impossible de vérifier automatiquement la date d'expiration de votre nom de domaine. "
                    "Connectez-vous à l'interface de votre registrar (OVH, Gandi, Namecheap…) "
                    "pour vérifier et renouveler votre domaine manuellement."
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
                f"Votre nom de domaine a expiré il y a {abs(days_remaining)} jour(s). "
                "Votre site et vos emails sont probablement inaccessibles. "
                "Connectez-vous immédiatement à votre registrar (OVH, Gandi…) pour renouveler "
                "avant que le domaine soit libéré et racheté par quelqu'un d'autre."
            )
        elif days_remaining < 7:
            score = 0
            status = "error"
            severity = SeverityLevel.CRITICAL
            recommendations.append(
                f"URGENT : Votre nom de domaine expire dans {days_remaining} jour(s). "
                "Sans renouvellement immédiat, votre site et vos emails deviendront inaccessibles. "
                "Connectez-vous dès maintenant à votre registrar pour renouveler."
            )
        elif days_remaining < 30:
            score = 30
            status = "warning"
            severity = SeverityLevel.HIGH
            recommendations.append(
                f"Votre nom de domaine expire dans {days_remaining} jours. "
                "Renouvelez-le rapidement pour éviter toute interruption de votre site et de vos emails. "
                "Connectez-vous à votre registrar (OVH, Gandi…) pour le renouveler."
            )
        elif days_remaining < 90:
            score = 60
            status = "warning"
            severity = SeverityLevel.MEDIUM
            recommendations.append(
                f"Votre nom de domaine expire dans {days_remaining} jours. "
                "Pensez à le renouveler prochainement pour ne pas risquer une interruption de service."
            )
        elif days_remaining < 180:
            score = 85
            status = "success"
            severity = SeverityLevel.LOW
            recommendations.append(
                f"Votre nom de domaine expire dans {days_remaining} jours. "
                "Anticipez le renouvellement pour éviter tout oubli de dernière minute."
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
