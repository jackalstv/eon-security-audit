from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from analyzers.domain_expiration import analyze_domain_expiration
from api.models import SeverityLevel


def _fake_whois(expiry_date, registrar="OVH"):
    """Simule la réponse de la commande whois avec une date d'expiration donnée."""
    w = MagicMock()
    w.expiration_date = expiry_date
    w.registrar = registrar
    return w


@patch('analyzers.domain_expiration.whois.whois')
def test_score_100_domaine_valide_longtemps(mock_whois):
    """Domaine valide 500 jours → score 100, sévérité LOW."""
    expiry = datetime.now(timezone.utc) + timedelta(days=500)
    mock_whois.return_value = _fake_whois(expiry)

    result = analyze_domain_expiration("example.com")

    assert result.score == 100
    assert result.severity == SeverityLevel.LOW


@patch('analyzers.domain_expiration.whois.whois')
def test_score_0_expire_dans_5_jours(mock_whois):
    """Domaine expirant dans 5 jours (< 7j) → score 0, CRITIQUE, message URGENT."""
    expiry = datetime.now(timezone.utc) + timedelta(days=5)
    mock_whois.return_value = _fake_whois(expiry)

    result = analyze_domain_expiration("example.com")

    assert result.score == 0
    assert result.severity == SeverityLevel.CRITICAL
    assert any("URGENT" in r for r in result.recommendations)


@patch('analyzers.domain_expiration.whois.whois')
def test_score_30_expire_dans_15_jours(mock_whois):
    """Domaine expirant dans 15 jours (7j < x < 30j) → score 30, HIGH."""
    expiry = datetime.now(timezone.utc) + timedelta(days=15)
    mock_whois.return_value = _fake_whois(expiry)

    result = analyze_domain_expiration("example.com")

    assert result.score == 30
    assert result.severity == SeverityLevel.HIGH


@patch('analyzers.domain_expiration.whois.whois')
def test_date_indisponible_retourne_warning(mock_whois):
    """WHOIS sans date d'expiration → score 50, statut warning."""
    mock_whois.return_value = _fake_whois(None)

    result = analyze_domain_expiration("example.com")

    assert result.score == 50
    assert result.status == "warning"
