import re
import validators
from urllib.parse import urlparse
from typing import Dict, Any


class DomainAnalyzer:
    """
    도메인 분석 클래스

    URL의 도메인을 분석하여 피싱 사이트 특징을 탐지합니다:
    - URL 유효성 검증
    - IP 주소 직접 사용 감지
    - 의심스러운 URL 패턴 (@ 포함, 긴 무작위 문자열 등)
    - 서브도메인 깊이 분석
    - 도메인 및 TLD 추출
    """

    # 의심스러운 URL 패턴
    SUSPICIOUS_PATTERNS = [
        r'@',  # URL에 @ 포함 (피싱 사이트가 사용자 속이기용)
        r'-{2,}',  # 연속된 하이픈
        r'[a-z0-9]{30,}',  # 30자 이상의 긴 무작위 문자열
    ]

    @staticmethod
    def analyze(url: str) -> Dict[str, Any]:
        """
        URL 도메인 분석

        Args:
            url: 분석할 URL

        Returns:
            dict: 분석 결과
                - is_valid_url: URL 유효성
                - is_ip_address: IP 주소 직접 사용 여부
                - has_suspicious_pattern: 의심스러운 패턴 존재 여부
                - subdomain_depth: 서브도메인 깊이
                - domain: 도메인 (예: example.com)
                - tld: 최상위 도메인 (예: com)
                - hostname: 전체 호스트명
        """
        result = {
            'is_valid_url': False,
            'is_ip_address': False,
            'has_suspicious_pattern': False,
            'subdomain_depth': 0,
            'domain': '',
            'tld': '',
            'hostname': ''
        }

        # URL 유효성 검증
        if not validators.url(url):
            return result

        result['is_valid_url'] = True

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            result['hostname'] = hostname

            # IP 주소 직접 사용 확인
            result['is_ip_address'] = DomainAnalyzer._is_ip_address(hostname)

            # 서브도메인 깊이 (점의 개수)
            result['subdomain_depth'] = hostname.count('.')

            # 의심스러운 패턴 확인
            result['has_suspicious_pattern'] = DomainAnalyzer._has_suspicious_pattern(url)

            # 도메인 추출
            parts = hostname.split('.')
            if len(parts) >= 2:
                result['domain'] = '.'.join(parts[-2:])
                result['tld'] = parts[-1]

        except Exception as e:
            # URL 파싱 실패 시 기본값 반환
            result['error'] = str(e)

        return result

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """
        IP 주소인지 확인

        Args:
            hostname: 호스트명

        Returns:
            bool: IP 주소 여부
        """
        # IPv4 패턴 (간단한 검사)
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, hostname):
            # 각 옥텟이 0-255 범위인지 확인
            try:
                parts = [int(p) for p in hostname.split('.')]
                return all(0 <= p <= 255 for p in parts)
            except ValueError:
                return False

        # IPv6 패턴 (간단한 검사)
        if ':' in hostname and not hostname.startswith('['):
            return True

        return False

    @staticmethod
    def _has_suspicious_pattern(url: str) -> bool:
        """
        의심스러운 URL 패턴 확인

        Args:
            url: 검사할 URL

        Returns:
            bool: 의심스러운 패턴 존재 여부
        """
        return any(
            re.search(pattern, url, re.IGNORECASE)
            for pattern in DomainAnalyzer.SUSPICIOUS_PATTERNS
        )

    @staticmethod
    def extract_domain(url: str) -> str:
        """
        URL에서 도메인만 추출

        Args:
            url: URL

        Returns:
            str: 도메인 (예: example.com)
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            parts = hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return hostname
        except Exception:
            return ''
