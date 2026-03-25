import dns.resolver
import requests
from api.models import ModuleResult, SeverityLevel

# Signatures de services vulnérables au subdomain takeover
# Source : https://github.com/EdOverflow/can-i-take-over-xyz
VULNERABLE_SIGNATURES = {
    "github": {
        "cname_contains": ["github.io"],
        "body_contains": ["There isn't a GitHub Pages site here"],
        "service": "GitHub Pages",
    },
    "heroku": {
        "cname_contains": ["herokuapp.com", "herokudns.com"],
        "body_contains": ["No such app", "herokucdn.com/error-pages/no-such-app"],
        "service": "Heroku",
    },
    "shopify": {
        "cname_contains": ["myshopify.com", "shopify.com"],
        "body_contains": ["Sorry, this shop is currently unavailable"],
        "service": "Shopify",
    },
    "fastly": {
        "cname_contains": ["fastly.net"],
        "body_contains": ["Fastly error: unknown domain"],
        "service": "Fastly",
    },
    "pantheon": {
        "cname_contains": ["pantheonsite.io"],
        "body_contains": ["The gods are wise", "404 error unknown site"],
        "service": "Pantheon",
    },
    "wordpress": {
        "cname_contains": ["wordpress.com"],
        "body_contains": ["Do you want to register"],
        "service": "WordPress.com",
    },
    "ghost": {
        "cname_contains": ["ghost.io"],
        "body_contains": ["The thing you were looking for is no longer here"],
        "service": "Ghost",
    },
    "surge": {
        "cname_contains": ["surge.sh"],
        "body_contains": ["project not found"],
        "service": "Surge.sh",
    },
    "azure": {
        "cname_contains": [
            "azurewebsites.net",
            "cloudapp.net",
            "trafficmanager.net",
            "blob.core.windows.net",
        ],
        "body_contains": ["404 Web Site not found"],
        "service": "Microsoft Azure",
    },
    "aws_s3": {
        "cname_contains": ["s3.amazonaws.com", "s3-website"],
        "body_contains": ["NoSuchBucket", "The specified bucket does not exist"],
        "service": "Amazon S3",
    },
    "unbounce": {
        "cname_contains": ["unbouncepages.com"],
        "body_contains": ["The requested URL was not found on this server"],
        "service": "Unbounce",
    },
    "sendgrid": {
        "cname_contains": ["sendgrid.net"],
        "body_contains": [],
        "service": "SendGrid",
    },
    "hubspot": {
        "cname_contains": ["hubspot.net", "hs-sites.com"],
        "body_contains": ["does not exist in our system"],
        "service": "HubSpot",
    },
    "zendesk": {
        "cname_contains": ["zendesk.com"],
        "body_contains": ["Help Center Closed"],
        "service": "Zendesk",
    },
}

# Sous-domaines communs à énumérer (ANSSI recommande une surface minimale exposée)
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "test", "portal", "admin", "support", "docs", "cdn", "app", "beta",
    "status", "help", "connect", "git", "ci", "assets", "static", "media",
]


def _resolve_cname(subdomain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


def _check_http_body(subdomain: str, signatures: list[str]) -> bool:
    if not signatures:
        return False
    for scheme in ["https", "http"]:
        try:
            response = requests.get(
                f"{scheme}://{subdomain}",
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True,
            )
            body = response.text.lower()
            if any(sig.lower() in body for sig in signatures):
                return True
        except Exception:
            continue
    return False


def _is_dangling_cname(cname: str, signatures: dict) -> tuple[bool, str]:

    cname_lower = cname.lower()
    for _, sig in signatures.items():
        for pattern in sig["cname_contains"]:
            if pattern in cname_lower:
                return True, sig["service"]
    return False, ""


def detect_subdomain_takeover(domain: str) -> ModuleResult:

    try:
        score = 100  # on part de 100, on déduit selon les risques trouvés
        details = {}
        recommendations = []
        vulnerable_subdomains = []
        dangling_subdomains = []
        checked = 0

        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            cname = _resolve_cname(fqdn)

            if cname is None:
                continue  # sous-domaine inexistant, pas de risque

            checked += 1
            is_dangling, service_name = _is_dangling_cname(cname, VULNERABLE_SIGNATURES)

            if not is_dangling:
                continue

            # CNAME pointe vers un service connu vulnérable — vérifier si orphelin
            sig_key = next(
                (k for k, v in VULNERABLE_SIGNATURES.items()
                 if any(p in cname.lower() for p in v["cname_contains"])),
                None,
            )
            body_signatures = VULNERABLE_SIGNATURES[sig_key]["body_contains"] if sig_key else []
            is_orphan = _check_http_body(fqdn, body_signatures)

            entry = {
                "subdomain": fqdn,
                "cname": cname,
                "service": service_name,
            }

            if is_orphan:
                entry["status"] = "VULNERABLE — service orphelin détecté"
                vulnerable_subdomains.append(entry)
                score -= 40
                recommendations.append(
                    f"CRITIQUE : {fqdn} pointe vers {service_name} via CNAME orphelin "
                    f"({cname}) — supprimer l'enregistrement DNS ou revendiquer la ressource"
                )
            else:
                entry["status"] = "CNAME vers service tiers (à surveiller)"
                dangling_subdomains.append(entry)
                score -= 10
                recommendations.append(
                    f"Surveiller {fqdn} → {cname} ({service_name}) : "
                    f"supprimer ce CNAME si le service n'est plus utilisé"
                )

        score = max(0, score)
        details["subdomains_checked"] = checked
        details["vulnerable"] = vulnerable_subdomains
        details["at_risk"] = dangling_subdomains

        # Recommandation générale ANSSI
        if not recommendations:
            recommendations.append(
                "Aucun CNAME orphelin détecté sur les sous-domaines courants"
            )
        recommendations.append(
            "ANSSI recommande de supprimer tout enregistrement DNS pointant vers "
            "des ressources tierces non utilisées (Guide d'hygiène informatique, mesure 13)"
        )

        # Sévérité
        if vulnerable_subdomains:
            status = "error"
            severity = SeverityLevel.CRITICAL
        elif dangling_subdomains:
            status = "warning"
            severity = SeverityLevel.HIGH
        elif score >= 80:
            status = "success"
            severity = SeverityLevel.LOW
        else:
            status = "warning"
            severity = SeverityLevel.MEDIUM

        return ModuleResult(
            module_name="Subdomain Takeover",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations,
        )

    except Exception as e:
        return ModuleResult(
            module_name="Subdomain Takeover",
            status="error",
            severity=SeverityLevel.HIGH,
            score=0,
            details={"error": str(e)},
            recommendations=["Vérifier la résolution DNS et la connectivité réseau"],
        )