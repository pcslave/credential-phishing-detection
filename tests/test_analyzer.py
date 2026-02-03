import pytest
from app.analyzer.domain_analyzer import DomainAnalyzer
from app.analyzer.blacklist import BlacklistManager


class TestDomainAnalyzer:
    """DomainAnalyzer 테스트"""

    def test_detect_ip_address(self):
        """IP 주소 직접 사용 탐지"""
        result = DomainAnalyzer.analyze("http://192.168.1.1/login")
        assert result['is_valid_url'] is True
        assert result['is_ip_address'] is True
        assert result['hostname'] == '192.168.1.1'

    def test_detect_suspicious_pattern_with_at_sign(self):
        """@ 포함 의심스러운 URL 패턴 탐지"""
        result = DomainAnalyzer.analyze("https://user@example.com/login")
        assert result['has_suspicious_pattern'] is True

    def test_detect_suspicious_pattern_with_long_string(self):
        """긴 무작위 문자열 패턴 탐지"""
        result = DomainAnalyzer.analyze("https://abcdefghijklmnopqrstuvwxyz123456789.com/login")
        assert result['has_suspicious_pattern'] is True

    def test_normal_url_no_suspicious_pattern(self):
        """정상 URL은 의심 패턴 없음"""
        result = DomainAnalyzer.analyze("https://www.google.com/login")
        assert result['has_suspicious_pattern'] is False
        assert result['is_ip_address'] is False

    def test_subdomain_depth(self):
        """서브도메인 깊이 계산"""
        test_cases = [
            ("https://example.com", 1),
            ("https://www.example.com", 2),
            ("https://sub.www.example.com", 3),
            ("https://deep.sub.www.example.com", 4),
        ]

        for url, expected_depth in test_cases:
            result = DomainAnalyzer.analyze(url)
            assert result['subdomain_depth'] == expected_depth

    def test_domain_extraction(self):
        """도메인 추출"""
        result = DomainAnalyzer.analyze("https://www.example.com/path")
        assert result['domain'] == 'example.com'
        assert result['tld'] == 'com'

    def test_invalid_url(self):
        """유효하지 않은 URL"""
        result = DomainAnalyzer.analyze("not-a-valid-url")
        assert result['is_valid_url'] is False

    def test_extract_domain_static_method(self):
        """extract_domain 정적 메서드"""
        assert DomainAnalyzer.extract_domain("https://www.example.com/path") == "example.com"
        assert DomainAnalyzer.extract_domain("https://sub.domain.co.uk/path") == "co.uk"

    def test_ipv6_detection(self):
        """IPv6 주소 감지"""
        result = DomainAnalyzer.analyze("http://[2001:db8::1]/login")
        # IPv6는 콜론 포함으로 감지
        assert result['is_ip_address'] is True

    def test_consecutive_hyphens(self):
        """연속된 하이픈 패턴"""
        result = DomainAnalyzer.analyze("https://suspicious--site.com/login")
        assert result['has_suspicious_pattern'] is True


class TestBlacklistManager:
    """BlacklistManager 테스트"""

    @pytest.fixture
    def temp_blacklist(self, tmp_path):
        """임시 블랙리스트 생성"""
        blacklist_file = tmp_path / "test_blacklist.json"
        return BlacklistManager(str(blacklist_file))

    def test_blacklist_initialization(self, temp_blacklist):
        """블랙리스트 초기화"""
        # 기본 블랙리스트가 자동 생성됨
        assert temp_blacklist.get_count() > 0

    def test_is_blacklisted(self, temp_blacklist):
        """블랙리스트 확인"""
        # 기본 블랙리스트에 포함된 도메인
        assert temp_blacklist.is_blacklisted("phishing-example.com") is True
        assert temp_blacklist.is_blacklisted("safe-site.com") is False

    def test_add_to_blacklist(self, temp_blacklist):
        """블랙리스트에 도메인 추가"""
        test_domain = "new-phishing-site.com"
        assert temp_blacklist.add(test_domain) is True
        assert temp_blacklist.is_blacklisted(test_domain) is True

    def test_add_duplicate_domain(self, temp_blacklist):
        """중복 도메인 추가 시도"""
        test_domain = "phishing-example.com"
        assert temp_blacklist.add(test_domain) is False  # 이미 존재

    def test_remove_from_blacklist(self, temp_blacklist):
        """블랙리스트에서 도메인 제거"""
        test_domain = "phishing-example.com"
        assert temp_blacklist.remove(test_domain) is True
        assert temp_blacklist.is_blacklisted(test_domain) is False

    def test_remove_non_existent_domain(self, temp_blacklist):
        """존재하지 않는 도메인 제거 시도"""
        assert temp_blacklist.remove("non-existent.com") is False

    def test_case_insensitive(self, temp_blacklist):
        """대소문자 구분 없음"""
        assert temp_blacklist.is_blacklisted("PHISHING-EXAMPLE.COM") is True
        assert temp_blacklist.is_blacklisted("Phishing-Example.Com") is True

    def test_get_all_blacklist(self, temp_blacklist):
        """블랙리스트 전체 목록 조회"""
        all_domains = temp_blacklist.get_all()
        assert isinstance(all_domains, set)
        assert "phishing-example.com" in all_domains

    def test_reload_blacklist(self, temp_blacklist):
        """블랙리스트 다시 로드"""
        initial_count = temp_blacklist.get_count()
        temp_blacklist.add("test-domain.com")
        assert temp_blacklist.get_count() == initial_count + 1

        temp_blacklist.reload()
        assert temp_blacklist.get_count() == initial_count + 1  # 저장되었으므로 유지
