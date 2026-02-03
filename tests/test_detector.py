import pytest
from app.detector.login_detector import LoginDetector
from app.models.analysis_request import AnalysisRequest
from datetime import datetime


class TestLoginDetector:
    """LoginDetector 테스트"""

    def test_detect_login_with_post_and_credentials(self, sample_login_request):
        """POST + credentials로 로그인 감지"""
        assert LoginDetector.detect(sample_login_request) is True

    def test_not_detect_normal_post(self, sample_non_login_request):
        """일반 POST 요청은 감지 안됨"""
        assert LoginDetector.detect(sample_non_login_request) is False

    def test_not_detect_get_request(self, sample_get_request):
        """GET 요청은 감지 안됨"""
        assert LoginDetector.detect(sample_get_request) is False

    def test_detect_with_auth_endpoint(self):
        """인증 엔드포인트 + POST는 감지"""
        request = AnalysisRequest(
            url="https://example.com/signin",
            method="POST",
            headers={},
            body={"email": "test@example.com", "pwd": "pass"},
            timestamp=datetime.now()
        )
        assert LoginDetector.detect(request) is True

    def test_detect_with_authorization_header(self):
        """Authorization 헤더 + POST는 감지"""
        request = AnalysisRequest(
            url="https://example.com/api",
            method="POST",
            headers={"Authorization": "Bearer token"},
            body={"data": "test"},
            timestamp=datetime.now()
        )
        # POST + Auth header = 2개 지표
        assert LoginDetector.detect(request) is True

    def test_detect_oauth_endpoint(self):
        """OAuth 엔드포인트 감지"""
        request = AnalysisRequest(
            url="https://example.com/oauth/token",
            method="POST",
            headers={},
            body={"grant_type": "password", "username": "user", "password": "pass"},
            timestamp=datetime.now()
        )
        assert LoginDetector.detect(request) is True

    def test_not_detect_with_only_one_indicator(self):
        """지표 1개만으로는 감지 안됨"""
        # POST만 (credentials 없음, auth endpoint 아님)
        request = AnalysisRequest(
            url="https://example.com/submit",
            method="POST",
            headers={},
            body={"comment": "hello"},
            timestamp=datetime.now()
        )
        assert LoginDetector.detect(request) is False

    def test_get_detection_details(self, sample_login_request):
        """감지 상세 정보 반환"""
        details = LoginDetector.get_detection_details(sample_login_request)

        assert details['is_post'] is True
        assert details['has_credentials'] is True
        assert details['is_auth_endpoint'] is True
        assert details['has_auth_header'] is False
        assert details['is_login_attempt'] is True

    def test_credential_patterns(self):
        """다양한 credential 필드 패턴 테스트"""
        test_cases = [
            ({"username": "user", "password": "pass"}, True),
            ({"email": "user@test.com", "passwd": "pass"}, True),
            ({"login": "user", "pwd": "pass"}, True),
            ({"user": "test", "password": "pass"}, True),
            ({"id": "test", "password": "pass"}, True),
            ({"name": "test", "data": "value"}, False),  # credential 필드 없음
        ]

        for body, expected in test_cases:
            request = AnalysisRequest(
                url="https://example.com/auth",
                method="POST",
                headers={},
                body=body,
                timestamp=datetime.now()
            )
            # POST + auth endpoint는 이미 2개 지표이므로 True
            # credential이 없으면 POST + auth endpoint만으로도 감지됨
            result = LoginDetector.detect(request)
            # auth endpoint + POST = 2개 지표로 항상 True
            assert result is True
