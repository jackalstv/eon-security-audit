
import requests
from config import settings
from api.models import ModuleResult, SeverityLevel

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_HEADERS = {"user-agent": "EON-Security-Audit/1.0"}


def _check_domain_as_breach_source(domain: str) -> tuple[list[dict], int]:
    #Vérifie si le domaine est lui-même source d'une fuite connue (endpoint public, sans clé)
    #Retourne (fuites_trouvées, total_fuites_vérifiées)
    response = requests.get(
        f"{HIBP_BASE_URL}/breaches",
        headers=HIBP_HEADERS,
        timeout=settings.REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    all_breaches = response.json()
    total = len(all_breaches)
    parts = domain.lower().split(".")
    # Cherche les 2 et 3 dernières parties pour couvrir .co.uk, .com.br, etc.
    candidates = {".".join(parts[-2:])}
    if len(parts) >= 3:
        candidates.add(".".join(parts[-3:]))
    matched = [
        b for b in all_breaches
        if any(c in b.get("Domain", "").lower() for c in candidates)
    ]
    return matched, total


def _check_emails_in_breaches(domain: str) -> dict:
    #Vérifie les emails @domaine dans toutes les fuites (endpoint payant, clé requise)
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


def _check_urlhaus(domain: str) -> dict:
    #Vérifie si le domaine distribue des malwares (URLhaus/abuse.ch — gratuit, sans clé)
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return {"query_status": "unavailable"}


def analyze_osint_breaches(domain: str) -> ModuleResult:
    #Interroge Have I Been Pwned et URLhaus pour détecter les fuites et menaces liées au domaine
    try:
        details: dict = {}
        recommendations: list[str] = []

        # 1. Vérification gratuite HIBP : le domaine est-il lui-même source de fuite ?
        source_breaches, total_hibp = _check_domain_as_breach_source(domain)
        details["hibp_base_verifiee"] = total_hibp
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

        # 2. Vérification URLhaus (gratuit) : malwares / réputation domaine
        urlhaus_data = _check_urlhaus(domain)
        urlhaus_status = urlhaus_data.get("query_status", "unavailable")
        urlhaus_listed = urlhaus_status == "is_host"

        if urlhaus_listed:
            url_count = urlhaus_data.get("url_count", 0)
            blacklists = urlhaus_data.get("blacklists", {})
            details["malware_urlhaus"] = {
                "liste": True,
                "urls_malveillantes": url_count,
                "spamhaus_dbl": blacklists.get("spamhaus_dbl", "not listed"),
                "surbl": blacklists.get("surbl", "not listed"),
            }
            recommendations.append(
                f"Domaine référencé dans URLhaus avec {url_count} URL malveillante(s). "
                "Vérifier immédiatement l'intégrité du serveur et des fichiers hébergés."
            )
        elif urlhaus_status == "no_results":
            details["malware_urlhaus"] = "Non référencé"
        else:
            details["malware_urlhaus"] = "Indisponible"

        # 3. Vérification avancée HIBP : emails @domaine dans fuites (clé API requise)
        if settings.HIBP_API_KEY:
            email_data = _check_emails_in_breaches(domain)
            emails_count = len(email_data)

            all_breaches_set: set[str] = set()
            for breach_list in email_data.values():
                all_breaches_set.update(breach_list)

            details["emails_compromis"] = emails_count
            details["fuites_distinctes"] = len(all_breaches_set)
            if all_breaches_set:
                details["fuites"] = sorted(all_breaches_set)

            if emails_count > 0:
                if emails_count <= 5:
                    recommendations.append(
                        f"{emails_count} adresse(s) email détectée(s) dans {len(all_breaches_set)} fuite(s). "
                        "Vérifier et modifier les mots de passe concernés."
                    )
                elif emails_count <= 20:
                    recommendations.append(
                        f"{emails_count} adresses email détectées dans {len(all_breaches_set)} fuite(s). "
                        "Forcer la réinitialisation des mots de passe et activer le MFA."
                    )
                else:
                    recommendations.append(
                        f"{emails_count} adresses email exposées dans {len(all_breaches_set)} fuite(s). "
                        "Forcer immédiatement la réinitialisation des mots de passe, "
                        "activer le MFA et alerter les utilisateurs concernés."
                    )
        else:
            details["emails_compromis"] = "non vérifié"
            if not source_breaches and not urlhaus_listed:
                recommendations.append(
                    f"Aucune fuite connue détectée pour ce domaine dans la base publique HIBP "
                    f"({total_hibp} fuites vérifiées). "
                    "Le scan des adresses email associées au domaine n'a pas pu être effectué "
                    "(clé API et propriété du domaine requises). "
                    "Vous pouvez vérifier manuellement vos adresses sur haveibeenpwned.com."
                )

        # Calcul du score
        emails_val = details.get("emails_compromis", 0)
        has_source_breach = details["source_fuite"]
        has_malware = urlhaus_listed

        if has_malware and has_source_breach:
            score, status, severity = 0, "error", SeverityLevel.CRITICAL
        elif has_malware or (has_source_breach and len(source_breaches) > 1):
            score, status, severity = 15, "error", SeverityLevel.CRITICAL
        elif has_source_breach:
            score, status, severity = 35, "warning", SeverityLevel.HIGH
        elif isinstance(emails_val, str):
            # Vérification des emails impossible (pas de clé API) : critère exclu du score,
            # on ne pénalise pas le domaine pour une limite du scanner.
            score, status, severity = 100, "success", SeverityLevel.LOW
        elif emails_val == 0:
            score, status, severity = 100, "success", SeverityLevel.LOW
        elif emails_val <= 5:
            score, status, severity = 60, "warning", SeverityLevel.MEDIUM
        elif emails_val <= 20:
            score, status, severity = 30, "warning", SeverityLevel.HIGH
        else:
            score, status, severity = 0, "error", SeverityLevel.CRITICAL

        return ModuleResult(
            module_name="OSINT Breaches",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations,
        )

    except Exception as e:
        return ModuleResult(
            module_name="OSINT Breaches",
            status="error",
            severity=SeverityLevel.HIGH,
            score=0,
            details={"error": str(e)},
            recommendations=["Impossible d'interroger Have I Been Pwned pour ce domaine."],
        )
