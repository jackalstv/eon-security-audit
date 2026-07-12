import ssl
import socket
import datetime
import requests
from cryptography import x509
from api.models import ModuleResult, SeverityLevel


def _fetch_expiry_ignore_validation(domain: str) -> datetime.datetime:
    #Lit la date d'expiration d'un certificat rejeté par le handshake (connexion sans validation)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der_cert).not_valid_after_utc


def _invalid_cert_result(domain: str, error: ssl.SSLCertVerificationError) -> ModuleResult:
    #Certificat rejeté par le handshake : diagnostic précis (expiré, auto-signé, mauvais domaine…)
    # verify_message donne la cause exacte ("certificate has expired", "self-signed certificate"…)
    reason = getattr(error, "verify_message", "")
    if not reason:
        reason = str(error)
    is_expired = "expired" in reason.lower()

    details = {
        "certificate": "EXPIRÉ" if is_expired else "INVALIDE",
        "verification_error": reason,
    }
    try:
        expiry = _fetch_expiry_ignore_validation(domain)
        details["expiration_date"] = expiry.strftime("%Y-%m-%d")
        days_expired = (datetime.datetime.now(datetime.timezone.utc) - expiry).days
        if days_expired >= 0:
            is_expired = True
            details["certificate"] = f"EXPIRÉ depuis {days_expired} jour(s)"
    except Exception:
        pass  # date non récupérable : le diagnostic reste basé sur le message du handshake

    if is_expired:
        recommendation = (
            "URGENT : Votre certificat de sécurité est expiré. Votre site affiche actuellement "
            "une alerte de danger à tous vos visiteurs, qui ne peuvent plus y accéder sereinement. "
            "Contactez votre hébergeur immédiatement pour renouveler le certificat."
        )
    else:
        recommendation = (
            "Le certificat de sécurité de votre site est rejeté par les navigateurs "
            "(certificat auto-signé, autorité inconnue ou domaine non couvert par le certificat). "
            "Vos visiteurs voient une alerte de danger en arrivant sur votre site. "
            "Contactez votre hébergeur pour installer un certificat valide (Let's Encrypt est gratuit)."
        )

    return ModuleResult(
        module_name="SSL/TLS Security",
        status="error",
        severity=SeverityLevel.CRITICAL,
        score=0,
        details=details,
        recommendations=[recommendation],
    )


def analyze_ssl(domain: str) -> ModuleResult:
    #Analyse la configuration SSL/TLS d'un domaine
    try:
        score = 0
        details = {}
        recommendations = []

        # 1. Récupérer le certificat SSL et vérifier TLS
        # Le handshake valide le certificat : un certificat expiré/invalide échoue ici,
        # d'où le diagnostic dédié plutôt que le except générique de fin de fonction.
        context = ssl.create_default_context()
        try:
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # 4. Vérifier la version TLS (doit être ici, dans le with)
                    tls_version = ssock.version()
                    details['tls_version'] = tls_version
                    if tls_version in ['TLSv1.2', 'TLSv1.3']:
                        score += 30
                        details['tls_status'] = 'Sécurisé'
                    else:
                        details['tls_status'] = 'Version obsolète'
                        recommendations.append(
                            f"Votre site utilise un protocole de chiffrement dépassé ({tls_version}) "
                            "qui peut être contourné par des pirates. Les données échangées avec vos visiteurs "
                            "ne sont pas correctement protégées. "
                            "Contactez votre hébergeur ou prestataire technique pour mettre à jour la configuration TLS (version 1.2 minimum requise)."
                        )
        except ssl.SSLCertVerificationError as e:
            return _invalid_cert_result(domain, e)

        # 2. Vérifier la date d'expiration
        expiry_date_str = cert['notAfter']
        expiry_date = datetime.datetime.strptime(
            expiry_date_str, '%b %d %H:%M:%S %Y %Z'
        ).replace(tzinfo=datetime.timezone.utc)
        days_remaining = (expiry_date - datetime.datetime.now(datetime.timezone.utc)).days

        if days_remaining > 30:
            score += 40
            details['certificate'] = f'Valide (expire dans {days_remaining} jours)'
        elif days_remaining > 0:
            score += 20
            details['certificate'] = f'Expire bientôt ({days_remaining} jours)'
            recommendations.append(
                f"Votre certificat de sécurité expire dans {days_remaining} jours. "
                "Sans renouvellement, votre site affichera une alerte de sécurité à tous vos visiteurs, "
                "ce qui nuira à votre crédibilité. Contactez votre hébergeur pour le renouveler."
            )
        else:
            details['certificate'] = 'EXPIRÉ'
            recommendations.append(
                "URGENT : Votre certificat de sécurité est expiré. Votre site affiche actuellement "
                "une alerte de danger à tous vos visiteurs, qui ne peuvent plus y accéder sereinement. "
                "Contactez votre hébergeur immédiatement pour renouveler le certificat."
            )

        # 3. Vérifier HSTS
        hsts_unverifiable = False
        try:
            response = requests.get(f"https://{domain}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if 'Strict-Transport-Security' in response.headers:
                score += 30
                hsts_value = response.headers['Strict-Transport-Security']
                details['hsts'] = f'Activé ({hsts_value})'
            else:
                details['hsts'] = 'Désactivé'
                # Recommandation gérée par Security Headers pour éviter la duplication dans le rapport
        except Exception:
            hsts_unverifiable = True
            details['hsts'] = 'non évalué (site injoignable en HTTPS depuis le scanner)'

        # HSTS invérifiable : les 30 points sont exclus du barème.
        # On note sur les 70 points vérifiables (TLS + certificat), remis à l'échelle sur 100,
        # pour ne pas pénaliser le domaine à cause d'une limite du scanner.
        if hsts_unverifiable:
            details['bareme'] = 'score calculé sur les vérifications réalisables uniquement'
            score = round(score * 100 / 70)

        # Message positif uniquement si HSTS est réellement actif (pas juste invérifiable ou désactivé)
        if not recommendations and details['hsts'].startswith('Activé'):
            recommendations.append(
                "Votre configuration SSL/TLS est bonne : protocole sécurisé, certificat valide et HSTS actif."
            )

        # Détermination status & severity (ALIGNÉ DNS)
        if score >= 80:
            status = "success"
            severity = SeverityLevel.LOW
        elif score >= 50:
            status = "warning"
            severity = SeverityLevel.MEDIUM
        elif score >= 30:
            status = "warning"
            severity = SeverityLevel.HIGH
        else:
            status = "error"
            severity = SeverityLevel.CRITICAL

        return ModuleResult(
            module_name="SSL/TLS Security",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations
        )

    except Exception as e:
        return ModuleResult(
            module_name="SSL/TLS Security",
            status="error",
            severity=SeverityLevel.CRITICAL,
            score=0,
            details={"error": str(e)},
            recommendations=["Vérifier que le site utilise HTTPS"]
        )
