# Claude Development Guide - Credential Phishing Detection System

## 프로젝트 컨텍스트

이 프로젝트는 HTTP 요청을 분석하여 credential phishing 공격을 탐지하고 차단하는 보안 시스템입니다.
실시간으로 로그인 시도를 감지하고, 위험도를 평가하여 사용자를 보호합니다.

## 핵심 아키텍처

### 시스템 흐름
```
HTTP Request → Interceptor → Login Detector → Phishing Analyzer → Risk Engine → Response Handler
```

### 주요 컴포넌트

#### 1. Request Interceptor (요청 가로채기)
- **역할**: 모든 HTTP/HTTPS 요청을 가로채서 분석 파이프라인으로 전달
- **구현 위치**: `src/interceptor/` 또는 `lib/interceptor/`
- **주요 기능**:
  - 프록시 서버 또는 미들웨어로 구현
  - 요청 메타데이터 추출 (URL, 메서드, 헤더, 바디)
  - 비동기 분석을 위한 큐 관리

#### 2. Login Behavior Detector (로그인 행위 탐지)
- **역할**: HTTP 요청이 로그인 시도인지 판단
- **구현 위치**: `src/detector/` 또는 `lib/detector/`
- **탐지 기준**:
  - POST 메서드로 credential 형태의 데이터 전송
  - 폼 필드에 username/password/email 패턴 존재
  - Authorization 헤더 포함
  - `/login`, `/signin`, `/auth` 등의 엔드포인트 패턴
  - Content-Type이 form-data 또는 JSON

**구현 예시**:
```javascript
function isLoginAttempt(request) {
  const indicators = {
    hasCredentialFields: checkCredentialFields(request.body),
    isAuthEndpoint: /\/(login|signin|auth|authenticate)/i.test(request.url),
    hasAuthHeader: 'authorization' in request.headers,
    isPostMethod: request.method === 'POST'
  };

  return Object.values(indicators).filter(Boolean).length >= 2;
}
```

#### 3. Phishing Site Analyzer (피싱 사이트 분석)
- **역할**: 대상 웹사이트가 피싱 사이트인지 판별
- **구현 위치**: `src/analyzer/` 또는 `lib/analyzer/`
- **분석 항목**:
  - 도메인 유사성 검사 (Levenshtein distance)
  - SSL/TLS 인증서 검증
  - WHOIS 정보 조회 (도메인 등록일, 등록자 정보)
  - 알려진 피싱 DB 조회 (PhishTank, Google Safe Browsing API 등)
  - 페이지 구조 및 콘텐츠 분석 (DOM 구조, 로고 이미지 유사도)

**외부 API 활용**:
- Google Safe Browsing API
- VirusTotal API
- PhishTank API
- URLScan.io API

#### 4. Risk Assessment Engine (위험도 평가 엔진)
- **역할**: 수집된 데이터를 기반으로 위험도 산출 (상/중/하)
- **구현 위치**: `src/risk-engine/` 또는 `lib/risk-engine/`
- **평가 로직**:

```javascript
function assessRisk(analysisResult) {
  let score = 0;

  // 각 지표별 가중치 부여
  if (analysisResult.inPhishingDB) score += 50;
  if (analysisResult.typosquatting) score += 40;
  if (analysisResult.invalidSSL) score += 30;
  if (analysisResult.newDomain) score += 20;
  if (analysisResult.suspiciousURL) score += 25;
  if (analysisResult.hiddenWhois) score += 15;

  // 점수별 위험도 분류
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}
```

#### 5. Response Handler (응답 처리)
- **역할**: 위험도에 따라 적절한 응답 생성
- **구현 위치**: `src/handler/` 또는 `lib/handler/`
- **응답 유형**:
  - **위험도 상**: 경고 페이지 HTML 반환 (접근 차단)
  - **위험도 중**: 경고 메시지 + 계속 진행 옵션
  - **위험도 하**: 정상 요청 통과

## 기술 스택 가이드

### 권장 기술 스택

**백엔드**:
- Node.js + Express 또는 Fastify (미들웨어 기반 프록시)
- Python + Flask/FastAPI (ML 기반 분석이 필요한 경우)

**데이터베이스**:
- Redis (빠른 캐싱 및 임시 데이터 저장)
- PostgreSQL (분석 로그 및 블랙리스트 관리)

**라이브러리**:
- `axios` 또는 `node-fetch`: HTTP 요청
- `cheerio`: HTML 파싱 및 DOM 분석
- `tldextract`: 도메인 추출
- `leven`: 문자열 유사도 계산
- `ssl-checker`: SSL 인증서 검증

## 코딩 규칙 및 베스트 프랙티스

### 1. 보안 중심 개발
- **절대 금지**: 사용자의 credential(비밀번호, 토큰 등)을 로그에 기록하거나 저장
- **데이터 최소화**: 분석에 필요한 메타데이터만 추출
- **암호화**: 모든 내부 통신은 TLS 사용
- **입력 검증**: 모든 외부 입력에 대해 철저한 검증 및 sanitization

```javascript
// ❌ 나쁜 예
logger.info(`Login attempt with password: ${request.body.password}`);

// ✅ 좋은 예
logger.info(`Login attempt detected for URL: ${sanitizeUrl(request.url)}`);
```

### 2. 에러 처리
- 외부 API 호출 실패 시 graceful degradation
- 타임아웃 설정 (분석이 너무 오래 걸리면 스킵)
- 에러 발생 시에도 사용자 요청은 최대한 통과시킴 (false positive 최소화)

```javascript
async function analyzeWithTimeout(url, timeoutMs = 3000) {
  try {
    return await Promise.race([
      performAnalysis(url),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), timeoutMs)
      )
    ]);
  } catch (error) {
    logger.error(`Analysis failed: ${error.message}`);
    return { riskLevel: 'low', reason: 'analysis_failed' };
  }
}
```

### 3. 성능 최적화
- **캐싱**: 동일 도메인에 대한 반복 분석 방지 (TTL: 1시간)
- **비동기 처리**: 무거운 분석 작업은 백그라운드 큐로 처리
- **병렬 처리**: 독립적인 분석 항목은 Promise.all로 병렬 실행
- **Rate Limiting**: 외부 API 호출 제한 준수

```javascript
// 병렬 분석 예시
const [domainCheck, sslCheck, dbCheck] = await Promise.all([
  checkDomainSimilarity(url),
  validateSSLCert(url),
  queryPhishingDB(url)
]);
```

### 4. 테스트 전략
- **단위 테스트**: 각 컴포넌트별 독립 테스트
- **통합 테스트**: 전체 파이프라인 흐름 테스트
- **테스트 케이스**:
  - 정상 로그인 요청 (false positive 방지)
  - 알려진 피싱 사이트
  - 경계값 테스트 (위험도 점수 경계)
  - 에러 시나리오 (API 실패, 타임아웃 등)

## 데이터 모델

### AnalysisRequest
```typescript
interface AnalysisRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: any;
  timestamp: Date;
}
```

### AnalysisResult
```typescript
interface AnalysisResult {
  isLoginAttempt: boolean;
  isPhishing: boolean;
  riskLevel: 'high' | 'medium' | 'low';
  score: number;
  reasons: string[];
  action: 'blocked' | 'warned' | 'allowed';
  warningPageUrl?: string;
  metadata: {
    domainAge?: number;
    sslValid?: boolean;
    inBlacklist?: boolean;
    similarDomain?: string;
  };
}
```

## 개발 시 주의사항

### 1. False Positive 최소화
- 정상 사이트를 피싱으로 오판하면 사용자 경험 저하
- 여러 지표를 종합적으로 판단 (단일 지표로 차단하지 않음)
- 화이트리스트 관리 (대형 서비스는 사전 검증)

### 2. 개인정보 보호
- GDPR, 개인정보보호법 준수
- 로그에서 개인식별정보(PII) 제거
- 데이터 보관 기간 설정 (예: 분석 로그 30일 후 자동 삭제)

### 3. 확장성 고려
- 마이크로서비스 아키텍처 고려
- 각 분석 모듈을 독립적으로 배포 가능하도록 설계
- 메시지 큐(RabbitMQ, Kafka) 도입 검토

### 4. 모니터링 및 로깅
- 탐지율 및 오탐율 메트릭 추적
- Prometheus + Grafana로 실시간 모니터링
- 차단된 요청에 대한 상세 로그 기록

## API 설계 가이드

### RESTful API 엔드포인트

```
POST   /api/v1/analyze          # 요청 분석
GET    /api/v1/status/:id       # 분석 상태 조회
POST   /api/v1/report           # 피싱 사이트 신고
GET    /api/v1/blacklist        # 블랙리스트 조회 (관리자)
POST   /api/v1/whitelist        # 화이트리스트 추가 (관리자)
```

### 응답 코드 규칙
- `200`: 정상 분석 완료
- `202`: 분석 진행 중 (비동기)
- `400`: 잘못된 요청
- `429`: Rate limit 초과
- `500`: 내부 서버 오류

## 배포 및 운영

### 환경 변수
```bash
# 서버 설정
PORT=8080
NODE_ENV=production

# 외부 API 키
GOOGLE_SAFE_BROWSING_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx

# 데이터베이스
REDIS_URL=redis://localhost:6379
POSTGRES_URL=postgresql://user:pass@localhost/phishing_db

# 보안 설정
ENCRYPTION_KEY=xxx
JWT_SECRET=xxx

# 분석 설정
ANALYSIS_TIMEOUT_MS=3000
CACHE_TTL_SECONDS=3600
```

### 배포 체크리스트
- [ ] 환경 변수 모두 설정됨
- [ ] SSL/TLS 인증서 구성
- [ ] Rate limiting 활성화
- [ ] 로그 수집 시스템 연결
- [ ] 모니터링 대시보드 설정
- [ ] 백업 전략 수립
- [ ] 롤백 계획 준비

## 참고 자료

### 피싱 탐지 기술
- [Google Safe Browsing](https://developers.google.com/safe-browsing)
- [PhishTank](https://www.phishtank.com/)
- [OWASP Phishing Guide](https://owasp.org/www-community/attacks/Phishing)

### 도메인 분석
- [DNS Twister](https://dnstwister.report/) - 도메인 유사성 검사
- [URLScan.io](https://urlscan.io/) - URL 스캔 서비스

### 보안 베스트 프랙티스
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## Claude 작업 시 체크리스트

### 새 기능 추가 시
- [ ] 보안 영향 분석 완료
- [ ] 개인정보 처리 여부 확인
- [ ] 성능 영향 최소화 (타임아웃, 캐싱 고려)
- [ ] 에러 처리 추가
- [ ] 단위 테스트 작성
- [ ] API 문서 업데이트

### 코드 수정 시
- [ ] credential이 로그에 노출되지 않는지 확인
- [ ] false positive가 증가하지 않는지 검증
- [ ] 기존 테스트 통과 확인
- [ ] 성능 저하 여부 확인

### 리뷰 포인트
- 보안: credential 처리, 입력 검증, 에러 메시지
- 성능: N+1 쿼리, 불필요한 API 호출, 캐싱 누락
- 가독성: 복잡한 로직 주석, 매직 넘버 제거
- 확장성: 하드코딩된 값, 설정 가능한 파라미터

---

**이 문서는 프로젝트의 기술적 컨텍스트를 제공하며, 개발 시 지속적으로 업데이트해야 합니다.**
