from unittest.mock import patch, MagicMock
from analyzers.security_headers_analyzer import analyze_security_headers
from api.models import SeverityLevel


def _fake_response(headers):
    """Crée une fausse réponse HTTP avec les headers donnés."""
    mock = MagicMock()
    mock.headers = headers
    return mock


@patch('analyzers.security_headers_analyzer.requests.get')
def test_score_100_tous_headers_presents(mock_get):
    """Tous les headers de sécurité présents → score 100, aucune recommandation."""
    mock_get.return_value = _fake_response({
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
        'Referrer-Policy': 'no-referrer',
    })

    result = analyze_security_headers("example.com")

    assert result.score == 100
    assert result.severity == SeverityLevel.LOW
    assert result.recommendations == []


@patch('analyzers.security_headers_analyzer.requests.get')
def test_score_zero_aucun_header(mock_get):
    """Aucun header de sécurité → score 0, sévérité CRITIQUE."""
    mock_get.return_value = _fake_response({})

    result = analyze_security_headers("example.com")

    assert result.score == 0
    assert result.severity == SeverityLevel.CRITICAL
    assert len(result.recommendations) == 5  # un par header manquant


@patch('analyzers.security_headers_analyzer.requests.get')
def test_csp_seul_score_25(mock_get):
    """Uniquement CSP présente → score 25 (CSP vaut 25 points)."""
    mock_get.return_value = _fake_response({
        'Content-Security-Policy': "default-src 'self'",
    })

    result = analyze_security_headers("example.com")

    assert result.score == 25
    assert result.details["csp"] == "présente"
    assert result.details["x_frame_options"] == "absent"
