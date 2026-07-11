from unittest.mock import patch, MagicMock
from analyzers.osint_breaches import analyze_osint_breaches
from api.models import SeverityLevel


def _mock_hibp(breaches):
    """Simule la réponse de l'API HIBP (liste de toutes les fuites publiques)."""
    m = MagicMock()
    m.json.return_value = breaches
    return m


def _mock_urlhaus(query_status):
    """Simule la réponse d'URLhaus."""
    m = MagicMock()
    m.json.return_value = {"query_status": query_status}
    return m


@patch('analyzers.osint_breaches.settings')
@patch('analyzers.osint_breaches.requests.post')
@patch('analyzers.osint_breaches.requests.get')
def test_score_90_sans_cle_api_aucune_fuite(mock_get, mock_post, mock_settings):
    """Sans clé API et sans fuite connue → score 90 (LOW)."""
    mock_settings.HIBP_API_KEY = None
    mock_settings.REQUEST_TIMEOUT = 10
    mock_get.return_value = _mock_hibp([])                    # aucune fuite dans HIBP
    mock_post.return_value = _mock_urlhaus("no_results")      # pas dans URLhaus

    result = analyze_osint_breaches("example.com")

    assert result.score == 90
    assert result.severity == SeverityLevel.LOW


@patch('analyzers.osint_breaches.settings')
@patch('analyzers.osint_breaches.requests.post')
@patch('analyzers.osint_breaches.requests.get')
def test_score_35_si_domaine_source_de_fuite(mock_get, mock_post, mock_settings):
    """Domaine lui-même source d'une fuite HIBP → score 35 (HIGH)."""
    mock_settings.HIBP_API_KEY = None
    mock_settings.REQUEST_TIMEOUT = 10
    mock_get.return_value = _mock_hibp([{
        "Domain": "example.com",
        "Name": "ExampleBreach",
        "BreachDate": "2023-01-01",
        "PwnCount": 5000,
        "DataClasses": ["Email addresses", "Passwords"],
    }])
    mock_post.return_value = _mock_urlhaus("no_results")

    result = analyze_osint_breaches("example.com")

    assert result.score == 35
    assert result.severity == SeverityLevel.HIGH
    assert result.details["source_fuite"] is True


@patch('analyzers.osint_breaches.settings')
@patch('analyzers.osint_breaches.requests.post')
@patch('analyzers.osint_breaches.requests.get')
def test_score_0_si_malware_et_fuite(mock_get, mock_post, mock_settings):
    """Malware URLhaus + source de fuite HIBP → score 0, CRITIQUE."""
    mock_settings.HIBP_API_KEY = None
    mock_settings.REQUEST_TIMEOUT = 10
    mock_get.return_value = _mock_hibp([{
        "Domain": "example.com",
        "Name": "ExampleBreach",
        "BreachDate": "2023-01-01",
        "PwnCount": 1000,
        "DataClasses": ["Passwords"],
    }])

    mock_urlhaus = MagicMock()
    mock_urlhaus.json.return_value = {
        "query_status": "is_host",
        "url_count": 3,
        "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
    }
    mock_post.return_value = mock_urlhaus

    result = analyze_osint_breaches("example.com")

    assert result.score == 0
    assert result.severity == SeverityLevel.CRITICAL
