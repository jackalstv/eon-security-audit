from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from analyzers.ssl_analyzer import analyze_ssl
from api.models import SeverityLevel


def _setup_ssl_mocks(cert_not_after, tls_version, hsts_value=None):
    """
    Prépare tous les mocks nécessaires pour analyser un site SSL.
    cert_not_after : date d'expiration du certificat au format 'Dec 31 23:59:59 2030 GMT'
    tls_version    : 'TLSv1.3', 'TLSv1.2', 'TLSv1' …
    hsts_value     : valeur du header HSTS si présent, None sinon
    """
    mock_ctx = MagicMock()
    mock_raw_conn = MagicMock()
    mock_ssock = MagicMock()

    # socket.create_connection() est utilisé comme context manager (with ... as sock)
    mock_raw_conn.__enter__.return_value = MagicMock()

    # context.wrap_socket() est aussi un context manager (with ... as ssock)
    mock_ssl_conn = MagicMock()
    mock_ssl_conn.__enter__.return_value = mock_ssock
    mock_ctx.wrap_socket.return_value = mock_ssl_conn

    mock_ssock.getpeercert.return_value = {'notAfter': cert_not_after}
    mock_ssock.version.return_value = tls_version

    mock_http = MagicMock()
    mock_http.headers = {'Strict-Transport-Security': hsts_value} if hsts_value else {}

    return mock_ctx, mock_raw_conn, mock_http


def test_score_100_cert_valide_tls13_hsts():
    """Certificat valide loin (2030) + TLSv1.3 + HSTS → score 100."""
    mock_ctx, mock_conn, mock_http = _setup_ssl_mocks(
        'Dec 31 23:59:59 2030 GMT', 'TLSv1.3', 'max-age=31536000'
    )

    with patch('analyzers.ssl_analyzer.ssl.create_default_context', return_value=mock_ctx), \
         patch('analyzers.ssl_analyzer.socket.create_connection', return_value=mock_conn), \
         patch('analyzers.ssl_analyzer.requests.get', return_value=mock_http):
        result = analyze_ssl("example.com")

    assert result.score == 100  # 30 (TLS) + 40 (cert valide) + 30 (HSTS)
    assert result.severity == SeverityLevel.LOW


def test_score_reduit_cert_expire():
    """Certificat expiré → recommandation urgente, sévérité HIGH."""
    mock_ctx, mock_conn, mock_http = _setup_ssl_mocks('Jan 01 00:00:00 2020 GMT', 'TLSv1.3')

    with patch('analyzers.ssl_analyzer.ssl.create_default_context', return_value=mock_ctx), \
         patch('analyzers.ssl_analyzer.socket.create_connection', return_value=mock_conn), \
         patch('analyzers.ssl_analyzer.requests.get', return_value=mock_http):
        result = analyze_ssl("example.com")

    assert result.score == 30  # 30 (TLS) + 0 (cert expiré) + 0 (pas HSTS)
    assert any("expiré" in r.lower() for r in result.recommendations)


def test_score_reduit_cert_expire_bientot():
    """Certificat expirant dans 15 jours → avertissement, score partiel."""
    expiry_soon = (datetime.now() + timedelta(days=15)).strftime('%b %d %H:%M:%S %Y GMT')
    mock_ctx, mock_conn, mock_http = _setup_ssl_mocks(expiry_soon, 'TLSv1.3')

    with patch('analyzers.ssl_analyzer.ssl.create_default_context', return_value=mock_ctx), \
         patch('analyzers.ssl_analyzer.socket.create_connection', return_value=mock_conn), \
         patch('analyzers.ssl_analyzer.requests.get', return_value=mock_http):
        result = analyze_ssl("example.com")

    assert result.score == 50  # 30 (TLS) + 20 (expire bientôt) + 0 (pas HSTS)
    assert any("expire" in r.lower() for r in result.recommendations)


def test_recommendation_tls_obsolete():
    """Version TLS obsolète → recommandation de mise à jour."""
    mock_ctx, mock_conn, mock_http = _setup_ssl_mocks('Dec 31 23:59:59 2030 GMT', 'TLSv1')

    with patch('analyzers.ssl_analyzer.ssl.create_default_context', return_value=mock_ctx), \
         patch('analyzers.ssl_analyzer.socket.create_connection', return_value=mock_conn), \
         patch('analyzers.ssl_analyzer.requests.get', return_value=mock_http):
        result = analyze_ssl("example.com")

    assert result.score == 40  # 0 (TLS obsolète) + 40 (cert valide) + 0 (pas HSTS)
    assert any("TLS" in r or "chiffrement" in r.lower() for r in result.recommendations)
