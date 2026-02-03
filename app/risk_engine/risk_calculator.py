from typing import List, Dict, Any, Tuple
from app.models.analysis_result import AnalysisResult, RiskLevel, Action, ExternalAPIResult
from app.config import settings
from app.utils.logger import log


class RiskCalculator:
    """
    위험도 계산 엔진

    내부 분석과 외부 API 결과를 통합하여 최종 위험도를 계산합니다.
    프로세스:
    1. 내부 분석 점수 계산 (블랙리스트, IP 주소, 의심 패턴 등)
    2. 외부 API 결과 평가 (가장 높은 위험도 선택)
    3. 내부 vs 외부 중 더 높은 위험도 선택
    4. Action 결정 (BLOCKED, WARNED, ALLOWED)
    """

    @staticmethod
    def calculate(
        internal_analysis: Dict[str, Any],
        external_results: List[ExternalAPIResult]
    ) -> AnalysisResult:
        """
        최종 위험도 계산

        Args:
            internal_analysis: 내부 분석 결과 (도메인 분석, 블랙리스트 등)
            external_results: 외부 API 결과 리스트

        Returns:
            AnalysisResult: 최종 분석 결과
        """
        # 1. 내부 분석 점수 계산
        internal_score, internal_reasons = RiskCalculator._calculate_internal_score(
            internal_analysis
        )

        # 2. 외부 API 결과 확인
        external_risk, external_reasons, decision_source = RiskCalculator._evaluate_external_apis(
            external_results
        )

        # 3. 최종 위험도 결정: 둘 중 더 높은 위험도 선택
        final_risk_level, final_score, final_reasons, final_source = RiskCalculator._merge_results(
            internal_score, internal_reasons, external_risk, external_reasons, decision_source
        )

        # 4. Action 결정
        action = RiskCalculator._determine_action(final_risk_level)

        # 5. 경고 페이지 URL (차단된 경우만)
        warning_url = None
        if action == Action.BLOCKED:
            warning_url = f"/warning?risk={final_risk_level.value}"

        return AnalysisResult(
            is_login_attempt=True,
            is_phishing=final_risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM],
            risk_level=final_risk_level,
            score=final_score,
            reasons=final_reasons,
            action=action,
            warning_page_url=warning_url,
            external_api_results=external_results,
            risk_decision_source=final_source
        )

    @staticmethod
    def _calculate_internal_score(analysis: Dict[str, Any]) -> Tuple[int, List[str]]:
        """
        내부 분석 점수 계산

        점수 체계:
        - 블랙리스트 등재: +50점
        - IP 주소 직접 사용: +40점
        - 의심스러운 패턴: +25점
        - 깊은 서브도메인 (>3): +15점

        Args:
            analysis: 내부 분석 결과

        Returns:
            Tuple[int, List[str]]: (점수, 이유 목록)
        """
        score = 0
        reasons = []

        # 블랙리스트 확인
        if analysis.get('in_blacklist'):
            score += 50
            reasons.append('알려진 피싱 사이트 블랙리스트에 등재됨')

        # IP 주소 사용
        if analysis.get('is_ip_address'):
            score += 40
            reasons.append('도메인 대신 IP 주소를 직접 사용')

        # 의심스러운 URL 패턴
        if analysis.get('has_suspicious_pattern'):
            score += 25
            reasons.append('의심스러운 URL 패턴 감지 (@, 긴 무작위 문자열 등)')

        # 깊은 서브도메인
        subdomain_depth = analysis.get('subdomain_depth', 0)
        if subdomain_depth > 3:
            score += 15
            reasons.append(f'비정상적으로 깊은 서브도메인 ({subdomain_depth}단계)')

        # URL 유효하지 않음
        if not analysis.get('is_valid_url'):
            score += 30
            reasons.append('유효하지 않은 URL 형식')

        return score, reasons

    @staticmethod
    def _evaluate_external_apis(
        results: List[ExternalAPIResult]
    ) -> Tuple[RiskLevel, List[str], str]:
        """
        외부 API 결과 평가 (가장 높은 위험도 반환)

        Args:
            results: 외부 API 결과 리스트

        Returns:
            Tuple[RiskLevel, List[str], str]: (위험도, 이유 목록, 결정한 API 이름)
        """
        if not results:
            return RiskLevel.LOW, [], "internal"

        # 위험도 우선순위
        risk_priority = {
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1
        }

        # 가장 높은 위험도 찾기
        highest_result = max(results, key=lambda r: risk_priority[r.risk_level])

        reasons = []
        for result in results:
            if result.is_threat:
                reason = f"{result.api_name}: 위협 탐지 (위험도: {result.risk_level.value})"

                # API별 상세 정보 추가
                if 'threat_types' in result.details:
                    threat_types = result.details['threat_types']
                    if threat_types:
                        reason += f" - {', '.join(threat_types)}"

                elif 'malicious_count' in result.details:
                    malicious = result.details['malicious_count']
                    suspicious = result.details.get('suspicious_count', 0)
                    reason += f" - {malicious}개 스캐너가 악성으로 판단"
                    if suspicious > 0:
                        reason += f", {suspicious}개 의심"

                elif 'phish_id' in result.details and result.details['phish_id']:
                    phish_id = result.details['phish_id']
                    reason += f" - Phish ID: {phish_id}"

                reasons.append(reason)

        return highest_result.risk_level, reasons, highest_result.api_name

    @staticmethod
    def _merge_results(
        internal_score: int,
        internal_reasons: List[str],
        external_risk: RiskLevel,
        external_reasons: List[str],
        external_source: str
    ) -> Tuple[RiskLevel, int, List[str], str]:
        """
        내부 분석과 외부 API 결과 통합
        더 높은 위험도를 최종 결과로 선택

        Args:
            internal_score: 내부 분석 점수
            internal_reasons: 내부 분석 이유
            external_risk: 외부 API 최고 위험도
            external_reasons: 외부 API 이유
            external_source: 외부 API 이름

        Returns:
            Tuple[RiskLevel, int, List[str], str]: (최종 위험도, 점수, 이유 목록, 결정 소스)
        """
        # 내부 점수를 위험도로 변환
        if internal_score >= settings.risk_threshold_high:
            internal_risk = RiskLevel.HIGH
        elif internal_score >= settings.risk_threshold_medium:
            internal_risk = RiskLevel.MEDIUM
        else:
            internal_risk = RiskLevel.LOW

        risk_priority = {
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1
        }

        # 더 높은 위험도 선택
        if risk_priority[external_risk] > risk_priority[internal_risk]:
            log.info(
                f"외부 API 위험도가 더 높음: {external_risk.value} > {internal_risk.value} "
                f"(source: {external_source})"
            )
            # 외부 API 위험도가 더 높으면 외부 API 이유를 먼저, 내부 이유를 나중에
            all_reasons = external_reasons + internal_reasons
            return external_risk, internal_score, all_reasons, external_source

        else:
            log.info(
                f"내부 분석 위험도 사용: {internal_risk.value} "
                f"(score: {internal_score})"
            )
            # 내부 위험도가 더 높거나 같으면 내부 이유를 먼저, 외부 이유를 나중에
            all_reasons = internal_reasons + external_reasons
            return internal_risk, internal_score, all_reasons, "internal"

    @staticmethod
    def _determine_action(risk_level: RiskLevel) -> Action:
        """
        위험도에 따른 액션 결정

        Args:
            risk_level: 위험도

        Returns:
            Action: 취할 액션
        """
        if risk_level == RiskLevel.HIGH:
            return Action.BLOCKED
        elif risk_level == RiskLevel.MEDIUM:
            return Action.WARNED
        else:
            return Action.ALLOWED

    @staticmethod
    def calculate_score_only(internal_analysis: Dict[str, Any]) -> int:
        """
        내부 분석 점수만 계산 (디버깅/테스트용)

        Args:
            internal_analysis: 내부 분석 결과

        Returns:
            int: 점수
        """
        score, _ = RiskCalculator._calculate_internal_score(internal_analysis)
        return score
