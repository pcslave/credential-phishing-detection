from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """애플리케이션 설정 관리"""

    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    log_level: str = "INFO"

    # External APIs Configuration (기본값: 사용 안함)
    enable_external_api: bool = False

    # Google Safe Browsing API
    use_google_safe_browsing: bool = False
    google_safe_browsing_api_key: str = ""

    # VirusTotal API
    use_virustotal: bool = False
    virustotal_api_key: str = ""

    # PhishTank API
    use_phishtank: bool = False

    # Analysis Settings
    analysis_timeout_seconds: int = 3

    # Risk Thresholds
    risk_threshold_high: int = 70
    risk_threshold_medium: int = 40

    # Security
    secret_key: str = "change-me-in-production"
    allowed_hosts: List[str] = ["*"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def get_enabled_apis(self) -> List[str]:
        """활성화된 외부 API 목록 반환"""
        apis = []
        if self.use_google_safe_browsing and self.google_safe_browsing_api_key:
            apis.append("google_safe_browsing")
        if self.use_virustotal and self.virustotal_api_key:
            apis.append("virustotal")
        if self.use_phishtank:
            apis.append("phishtank")
        return apis

    def is_external_api_enabled(self) -> bool:
        """외부 API 사용 여부 확인"""
        return self.enable_external_api and len(self.get_enabled_apis()) > 0


# 싱글톤 인스턴스
settings = Settings()
