from unittest.mock import patch, MagicMock
from analyzers.email_analyzer import analyze_email
from api.models import SeverityLevel


def _make_mx_record(hostname):
    """Crée un faux enregistrement MX avec l'attribut exchange."""
    m = MagicMock()
    m.exchange = hostname
    return m


def test_score_100_configuration_parfaite():
    """2 serveurs MX + STARTTLS + banner discret → score 100."""
    mx_records = [_make_mx_record("mail1.example.com"), _make_mx_record("mail2.example.com")]

    mock_smtp = MagicMock()
    mock_smtp.has_extn.return_value = True

    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"220 mail.example.com ESMTP"

    with patch('analyzers.email_analyzer.dns.resolver.resolve', return_value=mx_records), \
         patch('analyzers.email_analyzer.smtplib.SMTP', return_value=mock_smtp), \
         patch('analyzers.email_analyzer.socket.create_connection', return_value=mock_sock):
        result = analyze_email("example.com")

    assert result.score == 100
    assert result.severity == SeverityLevel.LOW


def test_m365_mx_pas_de_penalite_redondance():
    """Un seul MX Microsoft 365 → pas de pénalité de redondance."""
    mx_records = [_make_mx_record("eon.mail.protection.outlook.com")]

    # SMTP et socket inaccessibles (comportement normal sur Exchange)
    with patch('analyzers.email_analyzer.dns.resolver.resolve', return_value=mx_records), \
         patch('analyzers.email_analyzer.smtplib.SMTP', side_effect=Exception("Port closed")), \
         patch('analyzers.email_analyzer.socket.create_connection', side_effect=Exception("Port closed")):
        result = analyze_email("example.com")

    assert "Microsoft 365" in result.details["mx_redundancy"]
    assert not any("seul serveur" in r for r in result.recommendations)


def test_mx_unique_non_m365_recommandation_redondance():
    """Un seul MX générique → recommandation d'ajouter un serveur de secours."""
    mx_records = [_make_mx_record("mail.example.com")]

    mock_smtp = MagicMock()
    mock_smtp.has_extn.return_value = True
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"220 mail.example.com ESMTP"

    with patch('analyzers.email_analyzer.dns.resolver.resolve', return_value=mx_records), \
         patch('analyzers.email_analyzer.smtplib.SMTP', return_value=mock_smtp), \
         patch('analyzers.email_analyzer.socket.create_connection', return_value=mock_sock):
        result = analyze_email("example.com")

    assert any("seul serveur" in r for r in result.recommendations)


def test_aucun_mx_score_zero():
    """Sans MX, le score est 0, sévérité CRITIQUE."""
    with patch('analyzers.email_analyzer.dns.resolver.resolve', side_effect=Exception("NXDOMAIN")):
        result = analyze_email("example.com")

    assert result.score == 0
    assert result.severity == SeverityLevel.CRITICAL
