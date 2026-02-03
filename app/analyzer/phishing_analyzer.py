from typing import Dict, Any, List, Tuple
from app.analyzer.domain_analyzer import DomainAnalyzer
from app.analyzer.blacklist import BlacklistManager
from app.analyzer.external_api import external_api_manager
from app.models.analysis_result import ExternalAPIResult
from app.config import settings
from app.utils.logger import log


class PhishingAnalyzer:
    """
    피싱 사이트 종합 분석 클래스

    내부 분석(도메인, 블랙리스트)과 외부 API를 통합하여 URL을 분석합니다.
    프로세스:
    1. 도메인 기본 분석 (DomainAnalyzer)
    2. 블랙리스트 확인 (BlacklistManager)
    3. 외부 API 분석 (ExternalAPIManager) - 설정된 경우만
    """

    def __init__(self):
        """초기화: 블랙리스트 매니저 및 도메인 분석기 생성"""
        self.blacklist = BlacklistManager()
        self.domain_analyzer = DomainAnalyzer()

    async def analyze(self, url: str) -> Tuple[Dict[str, Any], List[ExternalAPIResult]]:
        """
        URL 종합 분석

        Args:
            url: 분석할 URL

        Returns:
            Tuple[Dict[str, Any], List[ExternalAPIResult]]:
                - 내부 분석 결과 (도메인, 블랙리스트 등)
                - 외부 API 결과 리스트
        """
        log.info(f"피싱 분석 시작: {url}")

        # 1. 도메인 기본 분석
        domain_analysis = self.domain_analyzer.analyze(url)

        # 2. 블랙리스트 확인
        domain = domain_analysis.get('domain', '')
        in_blacklist = False
        if domain:
            in_blacklist = self.blacklist.is_blacklisted(domain)
            if in_blacklist:
                log.warning(f"블랙리스트 도메인 감지: {domain}")

        # 내부 분석 결과 구성
        internal_result = {
            'url': url,
            'in_blacklist': in_blacklist,
            'is_ip_address': domain_analysis.get('is_ip_address', False),
            'has_suspicious_pattern': domain_analysis.get('has_suspicious_pattern', False),
            'subdomain_depth': domain_analysis.get('subdomain_depth', 0),
            'domain': domain,
            'tld': domain_analysis.get('tld', ''),
            'hostname': domain_analysis.get('hostname', ''),
            'is_valid_url': domain_analysis.get('is_valid_url', False)
        }

        log.info(
            f"내부 분석 완료: blacklist={in_blacklist}, "
            f"ip={internal_result['is_ip_address']}, "
            f"suspicious={internal_result['has_suspicious_pattern']}"
        )

        # 3. 외부 API 분석 (설정된 경우만)
        external_results = []
        if settings.enable_external_api and external_api_manager.is_enabled():
            try:
                log.info(f"외부 API 분석 시작: {external_api_manager.get_enabled_api_count()}개 API")
                external_results = await external_api_manager.check_url_all(url)
                log.info(f"외부 API 분석 완료: {len(external_results)}개 결과")
            except Exception as e:
                log.error(f"외부 API 분석 실패: {str(e)}")
        else:
            log.debug("외부 API 미사용")

        return internal_result, external_results

    def get_blacklist_count(self) -> int:
        """블랙리스트 도메인 개수 반환"""
        return self.blacklist.get_count()

    def add_to_blacklist(self, domain: str) -> bool:
        """
        블랙리스트에 도메인 추가

        Args:
            domain: 추가할 도메인

        Returns:
            bool: 추가 성공 여부
        """
        return self.blacklist.add(domain)

    def remove_from_blacklist(self, domain: str) -> bool:
        """
        블랙리스트에서 도메인 제거

        Args:
            domain: 제거할 도메인

        Returns:
            bool: 제거 성공 여부
        """
        return self.blacklist.remove(domain)
