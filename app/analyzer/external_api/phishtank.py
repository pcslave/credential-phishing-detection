from urllib.parse import quote
from app.analyzer.external_api.base_api import ExternalAPIBase
from app.models.analysis_result import RiskLevel, ExternalAPIResult


class PhishTankAPI(ExternalAPIBase):
    """
    PhishTank API 연동

    PhishTank의 무료 API를 사용하여 URL이 피싱 사이트인지 확인합니다.
    - API 키 불필요 (무료 공개 API)
    - 커뮤니티 기반 피싱 DB
    - API 문서: https://www.phishtank.com/api_info.php
    """

    API_URL = "https://checkurl.phishtank.com/checkurl/"

    async def check_url(self, url: str) -> ExternalAPIResult:
        """
        PhishTank에서 URL이 피싱 사이트인지 확인

        Args:
            url: 검사할 URL

        Returns:
            ExternalAPIResult: 분석 결과
        """
        # POST 데이터 구성
        data = {
            "url": url,
            "format": "json",
            "app_key": self.api_key if self.api_key else ""
        }

        # API 호출
        result = await self._make_request(
            'POST',
            self.API_URL,
            data=data,
            headers={
                "User-Agent": "phishing-detector/1.0"
            }
        )

        if not result['success']:
            return self._create_error_result(result.get('error', 'Unknown error'))

        # 응답 분석
        response_data = result['data']
        results = response_data.get('results', {})

        is_threat = results.get('in_database', False)
        is_valid = results.get('valid', True)

        # PhishTank에 등록된 경우 HIGH, 아니면 LOW
        risk_level = RiskLevel.HIGH if is_threat else RiskLevel.LOW

        return ExternalAPIResult(
            api_name="PhishTank",
            is_threat=is_threat,
            risk_level=risk_level,
            details={
                'in_database': is_threat,
                'valid': is_valid,
                'phish_id': results.get('phish_id', ''),
                'phish_detail_url': results.get('phish_detail_page', ''),
                'verified': results.get('verified', False),
                'verified_at': results.get('verified_at', '')
            },
            response_time_ms=result.get('response_time', 0)
        )
