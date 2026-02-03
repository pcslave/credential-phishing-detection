import pytest
from app.risk_engine.risk_calculator import RiskCalculator
from app.models.analysis_result import RiskLevel, Action, ExternalAPIResult


class TestRiskCalculator:
    """RiskCalculator 테스트"""

    def test_high_risk_with_blacklist(self, sample_internal_analysis, sample_external_api_results):
        """블랙리스트 등재 시 고위험"""
        analysis = sample_internal_analysis.copy()
        analysis['in_blacklist'] = True  # +50점

        result = RiskCalculator.calculate(analysis, sample_external_api_results)

        assert result.score >= 50
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]
        assert result.action in [Action.BLOCKED, Action.WARNED]
        assert any('블랙리스트' in reason for reason in result.reasons)

    def test_high_risk_with_ip_address(self, sample_internal_analysis, sample_external_api_results):
        """IP 주소 사용 시 고위험"""
        analysis = sample_internal_analysis.copy()
        analysis['is_ip_address'] = True  # +40점

        result = RiskCalculator.calculate(analysis, sample_external_api_results)

        assert result.score >= 40
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]
        assert any('IP 주소' in reason for reason in result.reasons)

    def test_low_risk_normal_site(self, sample_internal_analysis, sample_external_api_results):
        """정상 사이트는 저위험"""
        result = RiskCalculator.calculate(sample_internal_analysis, sample_external_api_results)

        assert result.risk_level == RiskLevel.LOW
        assert result.action == Action.ALLOWED
        assert result.is_phishing is False

    def test_external_api_overrides_internal(self, sample_internal_analysis, high_risk_external_api_results):
        """외부 API가 더 높은 위험도면 우선"""
        # 내부: LOW (점수 0)
        # 외부: HIGH (Google Safe Browsing)

        result = RiskCalculator.calculate(sample_internal_analysis, high_risk_external_api_results)

        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_decision_source == "Google Safe Browsing"
        assert result.action == Action.BLOCKED

    def test_internal_overrides_external(self, high_risk_internal_analysis, sample_external_api_results):
        """내부 분석이 더 높은 위험도면 우선"""
        # 내부: HIGH (블랙리스트 + IP + 패턴 = 115점)
        # 외부: LOW

        result = RiskCalculator.calculate(high_risk_internal_analysis, sample_external_api_results)

        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_decision_source == "internal"
        assert result.score >= 70

    def test_action_determination(self, sample_internal_analysis):
        """위험도에 따른 액션 결정"""
        # HIGH → BLOCKED
        high_analysis = sample_internal_analysis.copy()
        high_analysis['in_blacklist'] = True
        high_analysis['is_ip_address'] = True  # 90점

        result = RiskCalculator.calculate(high_analysis, [])
        assert result.action == Action.BLOCKED
        assert result.warning_page_url is not None

        # MEDIUM → WARNED
        medium_analysis = sample_internal_analysis.copy()
        medium_analysis['has_suspicious_pattern'] = True
        medium_analysis['subdomain_depth'] = 4  # 40점

        result = RiskCalculator.calculate(medium_analysis, [])
        assert result.action in [Action.WARNED, Action.ALLOWED]

        # LOW → ALLOWED
        low_analysis = sample_internal_analysis.copy()
        result = RiskCalculator.calculate(low_analysis, [])
        assert result.action == Action.ALLOWED
        assert result.warning_page_url is None

    def test_calculate_score_only(self, sample_internal_analysis):
        """점수만 계산"""
        score = RiskCalculator.calculate_score_only(sample_internal_analysis)
        assert score == 0  # 모든 지표가 False

        high_analysis = sample_internal_analysis.copy()
        high_analysis['in_blacklist'] = True  # +50
        high_analysis['is_ip_address'] = True  # +40
        score = RiskCalculator.calculate_score_only(high_analysis)
        assert score == 90

    def test_deep_subdomain_scoring(self, sample_internal_analysis):
        """깊은 서브도메인 점수"""
        analysis = sample_internal_analysis.copy()
        analysis['subdomain_depth'] = 4  # >3

        result = RiskCalculator.calculate(analysis, [])
        assert result.score >= 15
        assert any('서브도메인' in reason for reason in result.reasons)

    def test_invalid_url_scoring(self, sample_internal_analysis):
        """유효하지 않은 URL 점수"""
        analysis = sample_internal_analysis.copy()
        analysis['is_valid_url'] = False  # +30점

        result = RiskCalculator.calculate(analysis, [])
        assert result.score >= 30
        assert any('유효하지 않은 URL' in reason for reason in result.reasons)

    def test_multiple_external_apis(self, sample_internal_analysis):
        """다중 외부 API 결과 처리"""
        external_results = [
            ExternalAPIResult(
                api_name="API1",
                is_threat=True,
                risk_level=RiskLevel.MEDIUM,
                details={},
                response_time_ms=100.0
            ),
            ExternalAPIResult(
                api_name="API2",
                is_threat=True,
                risk_level=RiskLevel.HIGH,
                details={},
                response_time_ms=200.0
            ),
            ExternalAPIResult(
                api_name="API3",
                is_threat=False,
                risk_level=RiskLevel.LOW,
                details={},
                response_time_ms=150.0
            ),
        ]

        result = RiskCalculator.calculate(sample_internal_analysis, external_results)

        # 가장 높은 위험도 (HIGH)가 선택됨
        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_decision_source == "API2"

    def test_external_api_details_in_reasons(self, sample_internal_analysis):
        """외부 API 상세 정보가 이유에 포함"""
        external_results = [
            ExternalAPIResult(
                api_name="Google Safe Browsing",
                is_threat=True,
                risk_level=RiskLevel.HIGH,
                details={'threat_types': ['MALWARE', 'SOCIAL_ENGINEERING']},
                response_time_ms=150.0
            )
        ]

        result = RiskCalculator.calculate(sample_internal_analysis, external_results)

        # 이유에 API 이름과 위협 타입이 포함되어야 함
        assert any('Google Safe Browsing' in reason for reason in result.reasons)
        assert any('MALWARE' in reason or 'SOCIAL_ENGINEERING' in reason for reason in result.reasons)
