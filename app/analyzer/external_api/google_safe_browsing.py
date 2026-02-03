from app.analyzer.external_api.base_api import ExternalAPIBase
from app.models.analysis_result import RiskLevel, ExternalAPIResult


class GoogleSafeBrowsingAPI(ExternalAPIBase):
    """
    Google Safe Browsing API 연동

    Google의 Safe Browsing API v4를 사용하여 URL이 피싱/멀웨어 사이트인지 확인합니다.
    - 위협 타입: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE
    - API 문서: https://developers.google.com/safe-browsing/v4
    """

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def check_url(self, url: str) -> ExternalAPIResult:
        """
        URL이 피싱/멀웨어 사이트인지 확인

        Args:
            url: 검사할 URL

        Returns:
            ExternalAPIResult: 분석 결과
        """
        if not self.api_key:
            return self._create_error_result("API key not configured")

        # 요청 페이로드 구성
        payload = {
            "client": {
                "clientId": "credential-phishing-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        # API 호출
        result = await self._make_request(
            'POST',
            f"{self.API_URL}?key={self.api_key}",
            json=payload
        )

        if not result['success']:
            return self._create_error_result(result.get('error', 'Unknown error'))

        # 응답 분석
        data = result['data']
        matches = data.get('matches', [])
        is_threat = len(matches) > 0

        # 위협 타입 추출
        threat_types = [match.get('threatType', 'UNKNOWN') for match in matches]

        return ExternalAPIResult(
            api_name="Google Safe Browsing",
            is_threat=is_threat,
            risk_level=RiskLevel.HIGH if is_threat else RiskLevel.LOW,
            details={
                'matches': matches,
                'threat_types': threat_types,
                'threat_count': len(matches)
            },
            response_time_ms=result.get('response_time', 0)
        )
