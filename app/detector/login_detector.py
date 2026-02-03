import re
from typing import Dict, Any
from app.models.analysis_request import AnalysisRequest


class LoginDetector:
    """
    로그인 시도 탐지 클래스

    여러 지표를 종합하여 HTTP 요청이 로그인 시도인지 판단합니다:
    - POST 메서드 사용
    - credential 필드 포함 (username, password 등)
    - 인증 관련 엔드포인트 (/login, /signin, /auth 등)
    - Authorization 헤더 존재

    2개 이상의 지표가 충족되면 로그인 시도로 판단합니다.
    """

    # credential 필드 패턴
    CREDENTIAL_PATTERNS = [
        r'password|passwd|pwd',
        r'username|user|email|login|id'
    ]

    # 인증 엔드포인트 패턴
    AUTH_ENDPOINTS = [
        r'/login',
        r'/signin',
        r'/sign-in',
        r'/auth',
        r'/authenticate',
        r'/session',
        r'/oauth',
        r'/sso'
    ]

    @classmethod
    def detect(cls, request: AnalysisRequest) -> bool:
        """
        로그인 시도 여부 판단

        Args:
            request: 분석할 HTTP 요청

        Returns:
            bool: 로그인 시도 여부
        """
        indicators = {
            'is_post': cls._is_post_method(request),
            'has_credentials': cls._has_credential_fields(request),
            'is_auth_endpoint': cls._is_auth_endpoint(request),
            'has_auth_header': cls._has_auth_header(request)
        }

        # 2개 이상의 지표가 있으면 로그인 시도로 판단
        indicator_count = sum(indicators.values())
        return indicator_count >= 2

    @classmethod
    def _is_post_method(cls, request: AnalysisRequest) -> bool:
        """POST 메서드인지 확인"""
        return request.method.upper() == 'POST'

    @classmethod
    def _has_credential_fields(cls, request: AnalysisRequest) -> bool:
        """
        credential 필드 포함 여부 확인
        username/email + password 패턴이 모두 있어야 함
        """
        if not request.body:
            return False

        # body를 문자열로 변환 (dict, str 모두 처리)
        if isinstance(request.body, dict):
            body_str = str(request.body).lower()
        else:
            body_str = str(request.body).lower()

        # 모든 credential 패턴이 존재하는지 확인
        return all(
            re.search(pattern, body_str, re.IGNORECASE)
            for pattern in cls.CREDENTIAL_PATTERNS
        )

    @classmethod
    def _is_auth_endpoint(cls, request: AnalysisRequest) -> bool:
        """인증 관련 엔드포인트인지 확인"""
        url_lower = request.url.lower()
        return any(
            re.search(pattern, url_lower, re.IGNORECASE)
            for pattern in cls.AUTH_ENDPOINTS
        )

    @classmethod
    def _has_auth_header(cls, request: AnalysisRequest) -> bool:
        """Authorization 헤더가 있는지 확인"""
        return 'authorization' in [h.lower() for h in request.headers.keys()]

    @classmethod
    def get_detection_details(cls, request: AnalysisRequest) -> Dict[str, Any]:
        """
        감지 상세 정보 반환 (디버깅용)

        Returns:
            dict: 각 지표별 충족 여부
        """
        return {
            'is_post': cls._is_post_method(request),
            'has_credentials': cls._has_credential_fields(request),
            'is_auth_endpoint': cls._is_auth_endpoint(request),
            'has_auth_header': cls._has_auth_header(request),
            'is_login_attempt': cls.detect(request)
        }
