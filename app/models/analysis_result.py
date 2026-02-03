from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class RiskLevel(str, Enum):
    """위험도 레벨"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Action(str, Enum):
    """취할 액션"""
    BLOCKED = "blocked"  # 차단
    WARNED = "warned"    # 경고
    ALLOWED = "allowed"  # 허용


class ExternalAPIResult(BaseModel):
    """외부 API 개별 결과"""
    api_name: str = Field(..., description="API 이름 (예: Google Safe Browsing)")
    is_threat: bool = Field(..., description="위협 감지 여부")
    risk_level: RiskLevel = Field(..., description="해당 API가 판단한 위험도")
    details: Dict[str, Any] = Field(default_factory=dict, description="상세 정보")
    response_time_ms: float = Field(..., description="API 응답 시간 (밀리초)")


class AnalysisResult(BaseModel):
    """최종 분석 결과"""
    is_login_attempt: bool = Field(..., description="로그인 시도 여부")
    is_phishing: bool = Field(..., description="피싱 사이트 여부")
    risk_level: RiskLevel = Field(..., description="최종 위험도")
    score: int = Field(..., description="위험도 점수 (0-100)")
    reasons: List[str] = Field(default_factory=list, description="판단 근거 목록")
    action: Action = Field(..., description="취할 액션")
    warning_page_url: Optional[str] = Field(None, description="경고 페이지 URL (차단 시)")

    # 외부 API 결과 (설정된 경우만)
    external_api_results: List[ExternalAPIResult] = Field(
        default_factory=list,
        description="외부 API 분석 결과 목록"
    )

    # 최종 위험도를 결정한 소스
    risk_decision_source: str = Field(
        default="internal",
        description="위험도 결정 소스 (internal 또는 API 이름)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "is_login_attempt": True,
                "is_phishing": True,
                "risk_level": "high",
                "score": 85,
                "reasons": [
                    "도메인 대신 IP 주소를 직접 사용",
                    "알려진 피싱 사이트 블랙리스트에 등재됨"
                ],
                "action": "blocked",
                "warning_page_url": "/warning?risk=high",
                "external_api_results": [
                    {
                        "api_name": "Google Safe Browsing",
                        "is_threat": True,
                        "risk_level": "high",
                        "details": {"threat_types": ["SOCIAL_ENGINEERING"]},
                        "response_time_ms": 234.5
                    }
                ],
                "risk_decision_source": "Google Safe Browsing"
            }
        }
