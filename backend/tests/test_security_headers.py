
from analyzers.security_headers_analyzer import analyze_security_headers
from api.models import SeverityLevel


def test_security_headers_returns_valid_module_result():
    result = analyze_security_headers("example.com")

    assert result.module_name == "Security Headers"
    assert isinstance(result.score, int)
    assert 0 <= result.score <= 100
    assert result.severity in SeverityLevel
    assert isinstance(result.details, dict)
    assert isinstance(result.recommendations, list)
