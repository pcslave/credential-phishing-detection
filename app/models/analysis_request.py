from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any


class AnalysisRequest(BaseModel):
    """HTTP 요청 분석을 위한 데이터 모델"""

    url: str = Field(..., description="분석할 URL")
    method: str = Field(..., description="HTTP 메서드 (GET, POST 등)")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP 헤더")
    body: Optional[Dict[str, Any]] = Field(None, description="요청 본문 (POST 데이터)")
    timestamp: datetime = Field(default_factory=datetime.now, description="요청 시각")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com/login",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "user", "password": "pass"},
                "timestamp": "2026-02-03T10:30:00"
            }
        }
