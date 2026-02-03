import pytest
from datetime import datetime
from app.models.analysis_request import AnalysisRequest
from app.models.analysis_result import RiskLevel, ExternalAPIResult


@pytest.fixture
def sample_login_request():
    """로그인 요청 샘플"""
    return AnalysisRequest(
        url="https://example.com/login",
        method="POST",
        headers={"Content-Type": "application/json"},
        body={"username": "test", "password": "test123"},
        timestamp=datetime.now()
    )


@pytest.fixture
def sample_non_login_request():
    """일반 POST 요청 샘플 (로그인 아님)"""
    return AnalysisRequest(
        url="https://example.com/api/data",
        method="POST",
        headers={},
        body={"data": "test"},
        timestamp=datetime.now()
    )


@pytest.fixture
def sample_get_request():
    """GET 요청 샘플"""
    return AnalysisRequest(
        url="https://example.com/page",
        method="GET",
        headers={},
        body=None,
        timestamp=datetime.now()
    )


@pytest.fixture
def ip_address_login_request():
    """IP 주소 직접 사용 로그인 요청"""
    return AnalysisRequest(
        url="http://192.168.1.1/login",
        method="POST",
        headers={},
        body={"username": "test", "password": "test123"},
        timestamp=datetime.now()
    )


@pytest.fixture
def sample_internal_analysis():
    """내부 분석 결과 샘플"""
    return {
        'url': 'http://phishing-site.com/login',
        'in_blacklist': False,
        'is_ip_address': False,
        'has_suspicious_pattern': False,
        'subdomain_depth': 2,
        'domain': 'phishing-site.com',
        'tld': 'com',
        'hostname': 'phishing-site.com',
        'is_valid_url': True
    }


@pytest.fixture
def high_risk_internal_analysis():
    """고위험 내부 분석 결과 (블랙리스트 + IP)"""
    return {
        'url': 'http://192.168.1.1/login',
        'in_blacklist': True,
        'is_ip_address': True,
        'has_suspicious_pattern': True,
        'subdomain_depth': 0,
        'domain': '',
        'tld': '',
        'hostname': '192.168.1.1',
        'is_valid_url': True
    }


@pytest.fixture
def sample_external_api_results():
    """외부 API 결과 샘플"""
    return [
        ExternalAPIResult(
            api_name="Google Safe Browsing",
            is_threat=False,
            risk_level=RiskLevel.LOW,
            details={},
            response_time_ms=100.0
        ),
        ExternalAPIResult(
            api_name="VirusTotal",
            is_threat=False,
            risk_level=RiskLevel.LOW,
            details={},
            response_time_ms=200.0
        )
    ]


@pytest.fixture
def high_risk_external_api_results():
    """고위험 외부 API 결과"""
    return [
        ExternalAPIResult(
            api_name="Google Safe Browsing",
            is_threat=True,
            risk_level=RiskLevel.HIGH,
            details={'threat_types': ['SOCIAL_ENGINEERING']},
            response_time_ms=150.0
        ),
        ExternalAPIResult(
            api_name="VirusTotal",
            is_threat=True,
            risk_level=RiskLevel.MEDIUM,
            details={'malicious_count': 3},
            response_time_ms=250.0
        )
    ]
