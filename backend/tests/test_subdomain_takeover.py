from unittest.mock import patch
from analyzers.subdomain_takeover_analyzer import detect_subdomain_takeover
from api.models import SeverityLevel


@patch('analyzers.subdomain_takeover_analyzer._resolve_cname')
def test_score_100_aucun_cname_externe(mock_cname):
    """Aucun sous-domaine avec CNAME externe → score 100, aucun risque."""
    mock_cname.return_value = None  # tous les sous-domaines sans CNAME

    result = detect_subdomain_takeover("example.com")

    assert result.score == 100
    assert result.severity == SeverityLevel.LOW
    assert result.details["avec_cname_externe"] == 0


@patch('analyzers.subdomain_takeover_analyzer._check_http_body', return_value=True)
@patch('analyzers.subdomain_takeover_analyzer._resolve_cname')
def test_sous_domaine_vulnerable_score_critique(mock_cname, mock_body):
    """
    www.example.com pointe vers GitHub Pages abandonné (orphelin) → CRITIQUE.
    Note : les arguments suivent l'ordre des décorateurs de bas en haut.
    """
    def cname_effect(subdomain):
        if subdomain == "www.example.com":
            return "example.github.io"
        return None

    mock_cname.side_effect = cname_effect

    result = detect_subdomain_takeover("example.com")

    assert result.score == 60  # 100 - 40 (sous-domaine orphelin)
    assert result.severity == SeverityLevel.CRITICAL
    assert len(result.details["vulnerable"]) == 1


@patch('analyzers.subdomain_takeover_analyzer._check_http_body', return_value=False)
@patch('analyzers.subdomain_takeover_analyzer._resolve_cname')
def test_sous_domaine_dangling_score_high(mock_cname, mock_body):
    """
    blog.example.com pointe vers WordPress mais service encore actif → HIGH.
    Dangling = CNAME vers service tiers, mais pas orphelin.
    """
    def cname_effect(subdomain):
        if subdomain == "blog.example.com":
            return "example.wordpress.com"
        return None

    mock_cname.side_effect = cname_effect

    result = detect_subdomain_takeover("example.com")

    assert result.score == 90  # 100 - 10 (à surveiller)
    assert result.severity == SeverityLevel.HIGH
    assert len(result.details["at_risk"]) == 1
