
from analyzers.email_analyzer import analyze_email
from api.models import SeverityLevel


def test_email_returns_valid_module_result():
    result = analyze_email("example.com")

    assert result.module_name == "Email Security"
    assert isinstance(result.score, int)
    assert 0 <= result.score <= 100
    assert result.severity in SeverityLevel
    assert isinstance(result.details, dict)
    assert isinstance(result.recommendations, list)
