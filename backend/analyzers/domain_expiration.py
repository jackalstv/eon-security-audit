
import whois
from datetime import datetime, timezone
from api.models import ModuleResult, SeverityLevel


def analyze_domain_expiration(domain: str) -> ModuleResult:
    """Vérifie la date d'expiration du domaine via WHOIS"""
    try:
        details = {}
        recommendations = []

        w = whois.whois(domain)
        expiration_date = w.expiration_date

        # python-whois peut retourner une liste si plusieurs dates
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

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

        # Normaliser en datetime UTC naive pour la comparaison
        if expiration_date.tzinfo is not None:
            expiration_date = expiration_date.astimezone(timezone.utc).replace(tzinfo=None)

        now = datetime.utcnow()
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
