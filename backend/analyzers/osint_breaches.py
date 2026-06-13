
import requests
from config import settings
from api.models import ModuleResult, SeverityLevel

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_HEADERS = {"user-agent": "EON-Security-Audit/1.0"}


def _check_domain_as_breach_source(domain: str) -> list[dict]:
    """Vérifie si le domaine est lui-même source d'une fuite connue (endpoint public, sans clé)."""
    response = requests.get(
        f"{HIBP_BASE_URL}/breaches",
        headers=HIBP_HEADERS,
        timeout=settings.REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    all_breaches = response.json()
    # Chaque breach a un champ "Domain" — on filtre sur le domaine audité
    root_domain = domain.split(".")[-2] + "." + domain.split(".")[-1]
    return [
        b for b in all_breaches
        if root_domain.lower() in b.get("Domain", "").lower()
    ]


def _check_emails_in_breaches(domain: str) -> dict:
    """Vérifie les emails @domaine dans toutes les fuites (endpoint payant, clé requise)."""
    headers = {**HIBP_HEADERS, "hibp-api-key": settings.HIBP_API_KEY}
    response = requests.get(
        f"{HIBP_BASE_URL}/breacheddomain/{domain}",
        headers=headers,
        timeout=settings.REQUEST_TIMEOUT,
    )

    if response.status_code == 404:
        return {}
    if response.status_code == 401:
        raise PermissionError("Clé API HIBP invalide ou expirée")
    if response.status_code == 429:
        raise ConnectionError("Limite de requêtes HIBP atteinte (10 req/min)")

    response.raise_for_status()
    return response.json()


def analyze_osint_breaches(domain: str) -> ModuleResult:
    """Interroge Have I Been Pwned pour détecter les fuites de données liées au domaine"""
    try:
        details = {}
        recommendations = []

        # 1. Vérification gratuite : le domaine est-il lui-même une source de fuite ?
        source_breaches = _check_domain_as_breach_source(domain)
        details["source_fuite"] = len(source_breaches) > 0
        if source_breaches:
            details["fuites_source"] = [
                {
                    "nom": b["Name"],
                    "date": b["BreachDate"],
                    "comptes_exposes": b["PwnCount"],
                    "donnees": b["DataClasses"],
                }
                for b in source_breaches
            ]
            recommendations.append(
                f"Le domaine a été source de {len(source_breaches)} fuite(s) connue(s). "
                "Informer les utilisateurs et vérifier les mesures de sécurité en place."
            )

        # 2. Vérification avancée : emails @domaine dans d'autres fuites (clé API requise)
        if settings.HIBP_API_KEY:
            email_data = _check_emails_in_breaches(domain)
            emails_count = len(email_data)

            all_breaches: set[str] = set()
            for breach_list in email_data.values():
                all_breaches.update(breach_list)

            details["emails_compromis"] = emails_count
            details["fuites_distinctes"] = len(all_breaches)
            if all_breaches:
                details["fuites"] = sorted(all_breaches)

            if emails_count > 0:
                if emails_count <= 5:
                    recommendations.append(
                        f"{emails_count} adresse(s) email détectée(s) dans {len(all_breaches)} fuite(s). "
                        "Vérifier et modifier les mots de passe concernés."
                    )
                elif emails_count <= 20:
                    recommendations.append(
                        f"{emails_count} adresses email détectées dans {len(all_breaches)} fuite(s). "
                        "Forcer la réinitialisation des mots de passe et activer le MFA."
                    )
                else:
                    recommendations.append(
                        f"{emails_count} adresses email exposées dans {len(all_breaches)} fuite(s). "
                        "Forcer immédiatement la réinitialisation des mots de passe, "
                        "activer le MFA et alerter les utilisateurs concernés."
                    )
        else:
            details["emails_compromis"] = "non vérifié (HIBP_API_KEY non configurée)"
            recommendations.append(
                "Configurer HIBP_API_KEY dans .env pour vérifier les fuites d'emails du domaine. "
                "Clé disponible sur haveibeenpwned.com/API/Key"
            )

        # Calcul du score
        emails_count = details.get("emails_compromis", 0)
        has_source_breach = details["source_fuite"]

        if isinstance(emails_count, str):
            # Clé API absente : score basé uniquement sur la vérification gratuite
            if has_source_breach:
                score = 30
                status = "warning"
                severity = SeverityLevel.HIGH
            else:
                score = 75
                status = "warning"
                severity = SeverityLevel.MEDIUM
        elif emails_count == 0 and not has_source_breach:
            score = 100
            status = "success"
            severity = SeverityLevel.LOW
        elif emails_count <= 5 and not has_source_breach:
            score = 60
            status = "warning"
            severity = SeverityLevel.MEDIUM
        elif emails_count <= 20 or has_source_breach:
            score = 30
            status = "warning"
            severity = SeverityLevel.HIGH
        else:
            score = 0
            status = "error"
            severity = SeverityLevel.CRITICAL

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
