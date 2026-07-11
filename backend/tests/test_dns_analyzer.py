from unittest.mock import patch
from analyzers.dns_analyzer import analyze_dns
from api.models import SeverityLevel


def _resultat_checkdmarc(spf=True, dmarc=True, dmarc_record="v=DMARC1; p=reject", dnssec=True, mx=True):
    """Simule la réponse de checkdmarc selon les paramètres donnés."""
    return {
        'spf': {'valid': spf},
        'dmarc': {'valid': dmarc, 'record': dmarc_record} if dmarc else {'valid': False},
        'dnssec': dnssec,
        'mx': {'hosts': ['mail.example.com']} if mx else {},
    }


@patch('analyzers.dns_analyzer.checkdmarc.check_domains')
def test_score_100_quand_tout_est_configure(mock_check):
    """Cas idéal : SPF + DMARC p=reject + DNSSEC + MX → score 100, aucune recommandation."""
    mock_check.return_value = _resultat_checkdmarc()

    result = analyze_dns("example.com")

    assert result.score == 100
    assert result.severity == SeverityLevel.LOW
    assert result.recommendations == []


@patch('analyzers.dns_analyzer.checkdmarc.check_domains')
def test_score_reduit_si_spf_manquant(mock_check):
    """Sans SPF, le score perd 25 points et une recommandation est ajoutée."""
    mock_check.return_value = _resultat_checkdmarc(spf=False)

    result = analyze_dns("example.com")

    assert result.score == 75  # 100 - 25 (SPF manquant)
    assert any("SPF" in r for r in result.recommendations)


@patch('analyzers.dns_analyzer.checkdmarc.check_domains')
def test_recommendation_dmarc_quarantine(mock_check):
    """DMARC en mode quarantine → score inchangé mais recommandation de passer à p=reject."""
    mock_check.return_value = _resultat_checkdmarc(
        dmarc_record="v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
    )

    result = analyze_dns("example.com")

    assert result.score == 100  # quarantine ne pénalise pas le score
    assert any("p=reject" in r for r in result.recommendations)


@patch('analyzers.dns_analyzer.checkdmarc.check_domains')
def test_score_zero_rien_configure(mock_check):
    """Sans SPF, DMARC, DNSSEC et MX → score 0, sévérité CRITIQUE."""
    mock_check.return_value = _resultat_checkdmarc(spf=False, dmarc=False, dnssec=False, mx=False)

    result = analyze_dns("example.com")

    assert result.score == 0
    assert result.severity == SeverityLevel.CRITICAL
    assert len(result.recommendations) >= 4  # SPF, DMARC, DNSSEC, MX
