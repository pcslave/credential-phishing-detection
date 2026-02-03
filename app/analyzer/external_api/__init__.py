import asyncio
from typing import List, Tuple
from app.config import settings
from app.analyzer.external_api.base_api import ExternalAPIBase
from app.analyzer.external_api.google_safe_browsing import GoogleSafeBrowsingAPI
from app.analyzer.external_api.virustotal import VirusTotalAPI
from app.analyzer.external_api.phishtank import PhishTankAPI
from app.models.analysis_result import ExternalAPIResult, RiskLevel
from app.utils.logger import log


class ExternalAPIManager:
    """
    외부 API 통합 관리자

    설정된 외부 API들을 관리하고 다중 API에 병렬로 요청합니다.
    주요 기능:
    - 설정에 따라 API 자동 초기화
    - 모든 API에 병렬 요청 (asyncio.gather)
    - 가장 높은 위험도 선택
    - 각 API 결과 로깅
    """

    def __init__(self):
        """설정 파일을 기반으로 외부 API 초기화"""
        self.apis: List[ExternalAPIBase] = []
        self._initialize_apis()

    def _initialize_apis(self):
        """설정된 외부 API만 초기화"""
        if not settings.enable_external_api:
            log.info("외부 API 사용 안함 (ENABLE_EXTERNAL_API=False)")
            return

        # Google Safe Browsing API
        if settings.use_google_safe_browsing and settings.google_safe_browsing_api_key:
            self.apis.append(GoogleSafeBrowsingAPI(
                api_key=settings.google_safe_browsing_api_key,
                timeout=settings.analysis_timeout_seconds
            ))
            log.info("✓ Google Safe Browsing API 활성화")

        # VirusTotal API
        if settings.use_virustotal and settings.virustotal_api_key:
            self.apis.append(VirusTotalAPI(
                api_key=settings.virustotal_api_key,
                timeout=settings.analysis_timeout_seconds
            ))
            log.info("✓ VirusTotal API 활성화")

        # PhishTank API
        if settings.use_phishtank:
            self.apis.append(PhishTankAPI(
                api_key="",  # PhishTank는 API 키 선택사항
                timeout=settings.analysis_timeout_seconds
            ))
            log.info("✓ PhishTank API 활성화")

        if not self.apis:
            log.info("외부 API 미설정 (내부 분석만 사용)")
        else:
            log.info(f"총 {len(self.apis)}개 외부 API 활성화 완료")

    async def check_url_all(self, url: str) -> List[ExternalAPIResult]:
        """
        선택된 모든 외부 API에 병렬로 요청

        Args:
            url: 검사할 URL

        Returns:
            List[ExternalAPIResult]: 각 API의 분석 결과 리스트
        """
        if not self.apis:
            return []

        log.info(f"외부 API {len(self.apis)}개에 병렬 요청: {url}")

        # 모든 API를 병렬로 호출 (asyncio.gather)
        tasks = [api.check_url(url) for api in self.apis]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 에러 처리 및 로깅
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log.error(f"API {self.apis[i].api_name} 예외 발생: {str(result)}")
            elif isinstance(result, ExternalAPIResult):
                valid_results.append(result)
                log.info(
                    f"  - {result.api_name}: "
                    f"threat={result.is_threat}, "
                    f"risk={result.risk_level.value}, "
                    f"time={result.response_time_ms:.0f}ms"
                )

        return valid_results

    @staticmethod
    def get_highest_risk(results: List[ExternalAPIResult]) -> Tuple[RiskLevel, str]:
        """
        여러 API 결과 중 가장 높은 위험도 선택

        Args:
            results: 외부 API 결과 리스트

        Returns:
            Tuple[RiskLevel, str]: (최고 위험도, 결정한 API 이름)
        """
        if not results:
            return RiskLevel.LOW, "none"

        # 위험도 우선순위: HIGH(3) > MEDIUM(2) > LOW(1)
        risk_priority = {
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1
        }

        # 가장 높은 위험도를 가진 결과 찾기
        highest_result = max(
            results,
            key=lambda r: risk_priority[r.risk_level]
        )

        return highest_result.risk_level, highest_result.api_name

    def get_enabled_api_count(self) -> int:
        """활성화된 API 개수 반환"""
        return len(self.apis)

    def is_enabled(self) -> bool:
        """외부 API 사용 여부"""
        return len(self.apis) > 0


# 싱글톤 인스턴스
external_api_manager = ExternalAPIManager()


# Export
__all__ = [
    "ExternalAPIBase",
    "GoogleSafeBrowsingAPI",
    "VirusTotalAPI",
    "PhishTankAPI",
    "ExternalAPIManager",
    "external_api_manager"
]
