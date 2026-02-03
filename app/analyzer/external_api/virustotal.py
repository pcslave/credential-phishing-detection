import base64
from app.analyzer.external_api.base_api import ExternalAPIBase
from app.models.analysis_result import RiskLevel, ExternalAPIResult


class VirusTotalAPI(ExternalAPIBase):
    """
    VirusTotal API 연동

    VirusTotal API v3를 사용하여 URL 분석 결과를 조회합니다.
    - 70개 이상의 보안 엔진 분석 결과 제공
    - malicious, suspicious 카운트 기반 위험도 판단
    - API 문서: https://developers.virustotal.com/reference/overview
    """

    API_URL = "https://www.virustotal.com/api/v3/urls"

    async def check_url(self, url: str) -> ExternalAPIResult:
        """
        VirusTotal로 URL 분석

        Args:
            url: 검사할 URL

        Returns:
            ExternalAPIResult: 분석 결과
        """
        if not self.api_key:
            return self._create_error_result("API key not configured")

        # URL ID 생성 (base64 인코딩, 패딩 제거)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # API 헤더
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        # API 호출
        result = await self._make_request(
            'GET',
            f"{self.API_URL}/{url_id}",
            headers=headers
        )

        if not result['success']:
            return self._create_error_result(result.get('error', 'Unknown error'))

        # 응답 분석
        data = result['data'].get('data', {})
        attributes = data.get('attributes', {})
        last_analysis = attributes.get('last_analysis_stats', {})

        malicious = last_analysis.get('malicious', 0)
        suspicious = last_analysis.get('suspicious', 0)
        harmless = last_analysis.get('harmless', 0)
        undetected = last_analysis.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected

        # 위협 여부 판단
        is_threat = malicious > 0 or suspicious > 2

        # 위험도 판단
        if malicious > 5:
            risk_level = RiskLevel.HIGH
        elif malicious > 0 or suspicious > 2:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        return ExternalAPIResult(
            api_name="VirusTotal",
            is_threat=is_threat,
            risk_level=risk_level,
            details={
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'harmless_count': harmless,
                'undetected_count': undetected,
                'total_scanners': total,
                'reputation': attributes.get('reputation', 0),
                'last_analysis_date': attributes.get('last_analysis_date', 0)
            },
            response_time_ms=result.get('response_time', 0)
        )
