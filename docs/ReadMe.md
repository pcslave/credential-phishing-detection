# Credential Phishing Detection System

## 프로젝트 개요

HTTP 요청을 분석하여 로그인 행위를 탐지하고, credential phishing 사이트를 식별하여 사용자를 보호하는 보안 시스템입니다.

## 주요 기능

### 1. 로그인 행위 탐지
- 입력된 HTTP 요청을 실시간으로 분석
- 로그인 시도 패턴 및 credential 전송 행위 자동 감지
- POST 요청, 인증 헤더, 폼 데이터 등을 종합적으로 분석

### 2. Credential Phishing 사이트 식별
- 의심스러운 로그인 페이지 자동 탐지
- 도메인 유사성 검사 (typosquatting, homograph attack 등)
- 알려진 phishing 사이트 데이터베이스와 대조
- 웹페이지 구조 및 콘텐츠 분석

### 3. 위험도 평가 시스템
웹페이지의 위험 수준을 3단계로 분류합니다:

| 위험도 | 설명 | 조치 |
|--------|------|------|
| **상** | 명확한 phishing 징후 확인 | 접근 차단 및 경고 페이지 표시 |
| **중** | 의심스러운 패턴 감지 | 경고 메시지 표시 후 사용자 선택 |
| **하** | 정상 사이트로 판단 | 정상 접근 허용 |

### 4. 경고 페이지 응답
- 위험도 **상** 사이트 접근 시 자동으로 경고 페이지 제공
- 사용자에게 위험 요소 상세 안내
- 안전한 대체 경로 제시

## 시스템 아키텍처

```
[HTTP Request]
    ↓
[Request Interceptor]
    ↓
[Login Behavior Detector]
    ↓
[Phishing Site Analyzer]
    ↓
[Risk Assessment Engine]
    ↓
[Response Handler]
    ├─ 위험도 상 → [Warning Page]
    ├─ 위험도 중 → [Caution Message]
    └─ 위험도 하 → [Normal Response]
```

## 설치 방법

```bash
# 저장소 클론
git clone <repository-url>
cd my_project

# 의존성 설치
npm install
# 또는
pip install -r requirements.txt

# 환경 설정
cp .env.example .env
# .env 파일에서 필요한 설정 수정
```

## 사용 방법

### 기본 실행
```bash
# 서버 시작
npm start
# 또는
python main.py
```

### 설정 옵션
```bash
# 포트 지정
PORT=8080 npm start

# 로그 레벨 설정
LOG_LEVEL=debug npm start
```

## API 엔드포인트

### 요청 분석
```
POST /api/analyze
Content-Type: application/json

{
  "url": "https://example.com/login",
  "method": "POST",
  "headers": {...},
  "body": {...}
}
```

### 응답 예시
```json
{
  "isLoginAttempt": true,
  "isPhishing": true,
  "riskLevel": "high",
  "reasons": [
    "도메인이 알려진 정상 사이트와 유사함 (typosquatting 의심)",
    "SSL 인증서 발급일이 최근 (3일 전)",
    "WHOIS 정보가 은폐됨"
  ],
  "action": "blocked",
  "warningPageUrl": "/warning?id=abc123"
}
```

## 위험도 판단 기준

### 상 (High Risk)
- 알려진 phishing 데이터베이스에 등록된 사이트
- Typosquatting이 명확한 도메인
- SSL 인증서 이상 (자체 서명, 만료, 불일치 등)
- 의심스러운 URL 패턴 (IP 주소, 긴 서브도메인 등)

### 중 (Medium Risk)
- 새로 등록된 도메인 (30일 이내)
- 평판 정보가 부족한 사이트
- 일부 phishing 지표 감지

### 하 (Low Risk)
- 검증된 정상 사이트
- 충분한 평판 정보 보유
- phishing 지표 미발견

## 보안 고려사항

- 모든 요청 데이터는 암호화되어 전송됩니다
- 사용자 credential은 저장하지 않습니다 (프라이버시 보호)
- 분석 로그는 개인정보를 제외하고 저장됩니다
- GDPR 및 개인정보보호법 준수

## 기여 방법

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 `LICENSE` 파일을 참조하세요.

## 문의 및 지원

- 이슈 등록: [GitHub Issues](https://github.com/your-repo/issues)
- 이메일: security@example.com
- 문서: [Wiki](https://github.com/your-repo/wiki)

## 업데이트 로그

### v1.0.0 (2026-02-03)
- 초기 릴리스
- 로그인 행위 탐지 기능
- Credential phishing 사이트 식별
- 3단계 위험도 평가 시스템
- 고위험 사이트 경고 페이지

## 참고 자료

- [OWASP Phishing Guide](https://owasp.org/www-community/attacks/Phishing)
- [Anti-Phishing Working Group](https://apwg.org/)
- [PhishTank](https://www.phishtank.com/)

---

**⚠️ 주의**: 이 시스템은 보안 보조 도구이며, 완벽한 보호를 보장하지 않습니다. 사용자의 보안 의식과 함께 사용하시기 바랍니다.
