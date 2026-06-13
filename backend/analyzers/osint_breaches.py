
import requests
from config import settings
from api.models import ModuleResult, SeverityLevel

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"


def analyze_osint_breaches(domain: str) -> ModuleResult:
    """Interroge Have I Been Pwned pour détecter les fuites de données liées au domaine"""
    try:
        if not settings.HIBP_API_KEY:
            return ModuleResult(
                module_name="OSINT Breaches",
                status="info",
                severity=SeverityLevel.INFO,
                score=50,
                details={"status": "module non configuré"},
                recommendations=[
                    "Configurer HIBP_API_KEY dans le fichier .env pour activer la détection de fuites. "
                    "Clé disponible sur haveibeenpwned.com/API/Key"
                ]
            )

        headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "user-agent": "EON-Security-Audit/1.0",
        }

        response = requests.get(
            f"{HIBP_BASE_URL}/breacheddomain/{domain}",
            headers=headers,
            timeout=settings.REQUEST_TIMEOUT,
        )

        # Aucune fuite trouvée pour ce domaine
        if response.status_code == 404:
            return ModuleResult(
                module_name="OSINT Breaches",
                status="success",
                severity=SeverityLevel.LOW,
                score=100,
                details={"emails_compromis": 0, "fuites_distinctes": 0},
                recommendations=[]
            )

        if response.status_code == 401:
            return ModuleResult(
                module_name="OSINT Breaches",
                status="error",
                severity=SeverityLevel.HIGH,
                score=0,
                details={"error": "clé API HIBP invalide ou expirée"},
                recommendations=["Vérifier la clé HIBP_API_KEY dans le fichier .env"]
            )

        if response.status_code == 429:
            return ModuleResult(
                module_name="OSINT Breaches",
                status="error",
                severity=SeverityLevel.MEDIUM,
                score=0,
                details={"error": "limite de requêtes HIBP atteinte"},
                recommendations=["Réessayer dans quelques instants (limite : 10 requêtes/minute)"]
            )

        response.raise_for_status()

        # Format de réponse : {"alias": ["Breach1", "Breach2"], ...}
        data = response.json()
        emails_count = len(data)

        all_breaches: set[str] = set()
        for breach_list in data.values():
            all_breaches.update(breach_list)
        breach_count = len(all_breaches)

        details = {
            "emails_compromis": emails_count,
            "fuites_distinctes": breach_count,
            "fuites": sorted(all_breaches),
        }
        recommendations = []

        if emails_count == 0:
            score = 100
            status = "success"
            severity = SeverityLevel.LOW
        elif emails_count <= 5:
            score = 60
            status = "warning"
            severity = SeverityLevel.MEDIUM
            recommendations.append(
                f"{emails_count} adresse(s) email détectée(s) dans {breach_count} fuite(s). "
                "Vérifier et modifier les mots de passe concernés."
            )
        elif emails_count <= 20:
            score = 30
            status = "warning"
            severity = SeverityLevel.HIGH
            recommendations.append(
                f"{emails_count} adresses email détectées dans {breach_count} fuite(s). "
                "Forcer la réinitialisation des mots de passe et activer le MFA sur tous les comptes."
            )
        else:
            score = 0
            status = "error"
            severity = SeverityLevel.CRITICAL
            recommendations.append(
                f"{emails_count} adresses email exposées dans {breach_count} fuite(s). "
                "Forcer immédiatement la réinitialisation des mots de passe, "
                "activer le MFA et alerter les utilisateurs concernés."
            )

        return ModuleResult(
            module_name="OSINT Breaches",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations
        )

    except Exception as e:
        return ModuleResult(
            module_name="OSINT Breaches",
            status="error",
            severity=SeverityLevel.HIGH,
            score=0,
            details={"error": str(e)},
            recommendations=["Impossible d'interroger Have I Been Pwned pour ce domaine"]
        )
