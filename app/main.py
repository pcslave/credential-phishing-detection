from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.detector.login_detector import LoginDetector
from app.analyzer.phishing_analyzer import PhishingAnalyzer
from app.risk_engine.risk_calculator import RiskCalculator
from app.models.analysis_request import AnalysisRequest
from app.models.analysis_result import Action
from app.utils.logger import log, setup_logger


# 애플리케이션 시작/종료 시 실행될 코드
@asynccontextmanager
async def lifespan(app: FastAPI):
    """애플리케이션 라이프사이클 관리"""
    # 시작 시
    setup_logger(settings.log_level)
    log.info("=" * 60)
    log.info("Credential Phishing Detection System 시작")
    log.info(f"Version: 0.1.0")
    log.info(f"Host: {settings.host}:{settings.port}")
    log.info(f"Debug: {settings.debug}")
    log.info(f"외부 API 활성화: {settings.enable_external_api}")
    if settings.enable_external_api:
        enabled_apis = settings.get_enabled_apis()
        log.info(f"활성화된 외부 API: {', '.join(enabled_apis) if enabled_apis else '없음'}")
    log.info("=" * 60)

    yield

    # 종료 시
    log.info("Credential Phishing Detection System 종료")


# FastAPI 앱 생성
app = FastAPI(
    title="Credential Phishing Detection System",
    description="HTTP 요청을 분석하여 credential phishing 공격을 탐지하고 차단하는 보안 시스템",
    version="0.1.0",
    lifespan=lifespan
)

# CORS 설정 (필요한 경우)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_hosts,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# PhishingAnalyzer 싱글톤 인스턴스
phishing_analyzer = PhishingAnalyzer()


@app.get("/", response_class=HTMLResponse)
async def root():
    """루트 엔드포인트"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Credential Phishing Detection System</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            h1 { color: #2c3e50; }
            .info { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
            code { background: #34495e; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>🛡️ Credential Phishing Detection System</h1>
        <p>HTTP 요청을 분석하여 credential phishing 공격을 탐지하고 차단하는 보안 시스템</p>

        <div class="info">
            <h3>API 엔드포인트</h3>
            <ul>
                <li><code>POST /api/v1/analyze</code> - 요청 분석</li>
                <li><code>GET /health</code> - 헬스 체크</li>
                <li><code>GET /docs</code> - API 문서 (Swagger UI)</li>
                <li><code>GET /redoc</code> - API 문서 (ReDoc)</li>
            </ul>
        </div>
    </body>
    </html>
    """


@app.post("/api/v1/analyze")
async def analyze_request(request: AnalysisRequest):
    """
    요청 분석 API

    HTTP 요청을 분석하여 로그인 시도 여부를 감지하고,
    피싱 사이트인지 판단하여 위험도를 평가합니다.
    """
    log.info(f"분석 요청 수신: {request.method} {request.url}")

    try:
        # 1. 로그인 시도 감지
        is_login = LoginDetector.detect(request)

        if not is_login:
            log.info("로그인 시도 아님 - 정상 통과")
            return {
                "is_login_attempt": False,
                "action": "allowed",
                "message": "Not a login attempt"
            }

        log.info("✓ 로그인 시도 감지됨")

        # 2. 피싱 사이트 분석 (내부 + 외부 API)
        internal_analysis, external_results = await phishing_analyzer.analyze(request.url)

        # 3. 위험도 계산
        result = RiskCalculator.calculate(internal_analysis, external_results)

        # 4. 로그 기록
        log.info(
            f"분석 완료 - "
            f"URL: {request.url}, "
            f"위험도: {result.risk_level.value}, "
            f"점수: {result.score}, "
            f"액션: {result.action.value}, "
            f"결정 소스: {result.risk_decision_source}"
        )

        # 외부 API 결과 개별 로깅
        if result.external_api_results:
            for api_result in result.external_api_results:
                log.info(
                    f"  외부 API - {api_result.api_name}: "
                    f"threat={api_result.is_threat}, "
                    f"risk={api_result.risk_level.value}"
                )

        # 5. 차단된 경우 경고 페이지 반환
        if result.action == Action.BLOCKED:
            html_content = render_warning_page(request.url, result)
            return HTMLResponse(content=html_content, status_code=403)

        # 6. 경고 또는 허용
        return result

    except Exception as e:
        log.error(f"분석 중 오류 발생: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/health")
async def health_check():
    """
    헬스 체크

    시스템 상태 및 설정 정보를 반환합니다.
    """
    return {
        "status": "healthy",
        "version": "0.1.0",
        "external_apis_enabled": settings.enable_external_api,
        "active_apis": settings.get_enabled_apis(),
        "blacklist_count": phishing_analyzer.get_blacklist_count(),
        "settings": {
            "risk_threshold_high": settings.risk_threshold_high,
            "risk_threshold_medium": settings.risk_threshold_medium,
            "analysis_timeout": settings.analysis_timeout_seconds
        }
    }


def render_warning_page(url: str, result) -> str:
    """
    경고 페이지 HTML 렌더링

    Args:
        url: 차단된 URL
        result: 분석 결과

    Returns:
        str: HTML 콘텐츠
    """
    reasons_html = "\n".join(f"<li>{reason}</li>" for reason in result.reasons)

    # 외부 API 결과 표시
    api_results_html = ""
    if result.external_api_results:
        api_results_html = "<h3>외부 API 분석 결과</h3><ul>"
        for api_result in result.external_api_results:
            threat_emoji = "🚨" if api_result.is_threat else "✅"
            api_results_html += f"<li>{threat_emoji} {api_result.api_name}: {api_result.risk_level.value}</li>"
        api_results_html += "</ul>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>⚠️ 위험한 사이트 차단</title>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                max-width: 700px;
                margin: 50px auto;
                padding: 30px;
                background: #f5f5f5;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #e74c3c;
                margin-top: 0;
            }}
            .risk-badge {{
                display: inline-block;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: bold;
                background: #e74c3c;
                color: white;
            }}
            .url-box {{
                background: #ecf0f1;
                padding: 15px;
                border-radius: 5px;
                word-break: break-all;
                margin: 20px 0;
            }}
            ul {{
                line-height: 1.8;
            }}
            .footer {{
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #ecf0f1;
                color: #7f8c8d;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>⚠️ 위험한 사이트가 차단되었습니다</h1>

            <p>
                <span class="risk-badge">위험도: {result.risk_level.value.upper()}</span>
            </p>

            <div class="url-box">
                <strong>차단된 URL:</strong><br>
                {url}
            </div>

            <h3>차단 이유:</h3>
            <ul>
                {reasons_html}
            </ul>

            {api_results_html}

            <h3>📋 상세 정보</h3>
            <ul>
                <li><strong>위험도 점수:</strong> {result.score}/100</li>
                <li><strong>결정 소스:</strong> {result.risk_decision_source}</li>
                <li><strong>액션:</strong> {result.action.value}</li>
            </ul>

            <div class="footer">
                <p>이 사이트는 credential phishing 공격으로 의심되어 차단되었습니다.</p>
                <p>Credential Phishing Detection System v0.1.0</p>
            </div>
        </div>
    </body>
    </html>
    """


# 개발 서버 실행 (uvicorn 대신 직접 실행 시)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )
