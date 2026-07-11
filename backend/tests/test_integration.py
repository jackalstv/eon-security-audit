"""
Tests d'intégration — appels réseau réels vers des domaines connus.
Ces tests vérifient que la DÉTECTION est exacte, pas seulement la logique interne.
Ils nécessitent une connexion internet.
"""
import pytest
from analyzers.ssl_analyzer import analyze_ssl
from analyzers.security_headers_analyzer import analyze_security_headers
from analyzers.dns_analyzer import analyze_dns
from analyzers.email_analyzer import analyze_email
from analyzers.domain_expiration import analyze_domain_expiration
from analyzers.osint_breaches import analyze_osint_breaches
from api.models import SeverityLevel


def test_ssl_google_certificat_valide_et_tls_recent():
    """
    google.com a un certificat valide et utilise TLS 1.2 ou 1.3.
    Vérifie que l'analyseur SSL détecte correctement un site bien configuré.
    """
    result = analyze_ssl("google.com")

    assert result.score >= 70
    assert result.details["tls_version"] in ["TLSv1.2", "TLSv1.3"]
    assert "EXPIRÉ" not in result.details.get("certificate", "")


def test_security_headers_cloudflare_score_eleve():
    """
    cloudflare.com est connu pour avoir une configuration sécurité exemplaire.
    Vérifie que l'analyseur détecte bien les headers présents.
    """
    result = analyze_security_headers("cloudflare.com")

    assert result.score >= 75
    assert result.details["csp"] == "présente"


def test_dns_google_spf_et_dmarc_valides():
    """
    google.com a SPF, DMARC et MX configurés depuis des années.
    Vérifie que l'analyseur DNS détecte correctement une bonne configuration.
    Note : checkdmarc utilise son propre résolveur DNS — peut timeout en local,
    fonctionne sur le VPS.
    """
    result = analyze_dns("google.com")

    # checkdmarc timeout si le résolveur DNS de la machine est inaccessible
    if result.score == 0 and len(result.recommendations) >= 4:
        pytest.skip("Résolveur DNS de checkdmarc inaccessible depuis cette machine (test OK sur le VPS)")

    assert result.score >= 75
    assert result.details.get("spf") == "valid"
    assert "serveur" in result.details.get("mx", "")


def test_email_gmail_a_des_serveurs_mx():
    """
    gmail.com a plusieurs serveurs MX configurés.
    Vérifie que l'analyseur Email détecte bien les enregistrements MX.
    """
    result = analyze_email("gmail.com")

    assert "serveur(s) trouvé(s)" in result.details.get("mx_records", "")
    assert result.score >= 25  # au minimum les MX sont trouvés


def test_domain_expiration_google_valide_longtemps():
    """
    google.com renouvelle son domaine très longtemps à l'avance.
    Vérifie que l'analyseur WHOIS récupère et interprète correctement la date.
    """
    result = analyze_domain_expiration("google.com")

    assert result.score >= 85
    assert result.details.get("days_remaining", 0) > 180


def test_osint_google_pas_source_de_fuite():
    """
    google.com ne devrait pas être listé comme source de fuite dans HIBP.
    Vérifie que l'appel à l'API HIBP fonctionne et que la détection est cohérente.
    """
    result = analyze_osint_breaches("google.com")

    assert isinstance(result.score, int)
    assert result.details.get("source_fuite") is False
