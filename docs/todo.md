# Credential Phishing Detection System - TODO List

## 프로젝트 설정

### 초기 환경 구성
- [ ] 프로젝트 저장소 초기화 (git init)
- [ ] package.json 또는 requirements.txt 생성
- [ ] .gitignore 파일 설정
- [ ] .env.example 파일 작성
- [ ] 디렉토리 구조 생성 (src/, lib/, tests/, config/ 등)
- [ ] ESLint/Prettier 또는 Black/Flake8 설정
- [ ] TypeScript 설정 (tsconfig.json) - Node.js 사용 시

### 의존성 설치
- [ ] 웹 프레임워크 설치 (Express/Fastify/Flask/FastAPI)
- [ ] HTTP 클라이언트 라이브러리 (axios, node-fetch, requests)
- [ ] HTML 파싱 라이브러리 (cheerio, BeautifulSoup)
- [ ] 도메인 분석 라이브러리 (tldextract, url-parse)
- [ ] 문자열 유사도 라이브러리 (leven, python-Levenshtein)
- [ ] SSL 검증 라이브러리 (ssl-checker)
- [ ] 데이터베이스 클라이언트 (Redis, MariaDB)
- [ ] 로깅 라이브러리 (winston, pino, logging)
- [ ] 테스트 프레임워크 (Jest, pytest)

---

## 1. Request Interceptor (요청 가로채기 모듈)

### 기본 구조
- [ ] 프록시 서버 또는 미들웨어 기본 골격 구현
- [ ] HTTP/HTTPS 요청 가로채기 로직 구현
- [ ] 요청 메타데이터 추출 함수 작성
- [ ] 요청 큐 시스템 구현 (비동기 처리)

### 데이터 추출
- [ ] URL 파싱 및 추출
- [ ] HTTP 메서드 추출
- [ ] 요청 헤더 파싱
- [ ] 요청 바디 파싱 (JSON, form-data, URL-encoded)
- [ ] 쿼리 파라미터 추출

### 성능 최적화
- [ ] 요청 필터링 (정적 리소스 제외: .js, .css, .png 등)
- [ ] Rate limiting 구현
- [ ] 타임아웃 설정
- [ ] 에러 핸들링 및 재시도 로직

### 테스트
- [ ] GET 요청 가로채기 테스트
- [ ] POST 요청 가로채기 테스트
- [ ] 다양한 Content-Type 처리 테스트
- [ ] 대용량 요청 처리 테스트

---

## 2. Login Behavior Detector (로그인 행위 탐지 모듈)

### 패턴 감지 함수
- [ ] POST 메서드 감지
- [ ] 인증 헤더 감지 (Authorization, Cookie)
- [ ] credential 필드 감지 (username, password, email 등)
- [ ] 로그인 엔드포인트 패턴 매칭 (/login, /signin, /auth 등)
- [ ] Content-Type 검사 (application/json, multipart/form-data)

### 필드 분석
- [ ] JSON 바디에서 credential 필드 추출
- [ ] Form data에서 credential 필드 추출
- [ ] 일반적인 필드명 패턴 정의 (password, passwd, pwd, email, user 등)
- [ ] 정규표현식을 사용한 패턴 매칭

### 점수 기반 판단
- [ ] 로그인 지표별 가중치 설정
- [ ] 종합 점수 계산 로직
- [ ] 임계값 기반 로그인 시도 판단 함수

### 테스트
- [ ] 정상 로그인 요청 감지 테스트
- [ ] False positive 케이스 테스트 (일반 POST 요청)
- [ ] 다양한 로그인 폼 형식 테스트
- [ ] Edge case 테스트 (비표준 필드명 등)

---

## 3. Phishing Site Analyzer (피싱 사이트 분석 모듈)

### 도메인 분석
- [ ] 도메인 추출 함수 구현
- [ ] TLD(Top Level Domain) 분석
- [ ] 서브도메인 분석
- [ ] 도메인 유사성 검사 (Levenshtein distance)
- [ ] Typosquatting 탐지 (화이트리스트 기반)
- [ ] Homograph attack 탐지 (유니코드 혼동 문자)
- [ ] IP 주소 직접 사용 탐지

### WHOIS 조회
- [ ] WHOIS API 연동
- [ ] 도메인 등록일 조회
- [ ] 도메인 등록자 정보 조회
- [ ] WHOIS 정보 은닉 여부 확인
- [ ] 새 도메인 판단 (30일 이내 등록)

### SSL/TLS 인증서 검증
- [ ] SSL 인증서 존재 여부 확인
- [ ] 인증서 만료일 확인
- [ ] 인증서 발급 기관 검증
- [ ] 인증서와 도메인 일치 여부 확인
- [ ] 자체 서명 인증서 탐지

### 외부 피싱 DB 조회
- [ ] Google Safe Browsing API 연동
- [ ] PhishTank API 연동
- [ ] VirusTotal API 연동
- [ ] URLScan.io API 연동
- [ ] 로컬 블랙리스트 DB 조회

### 페이지 콘텐츠 분석
- [ ] 웹페이지 HTML 다운로드
- [ ] DOM 구조 분석 (cheerio, BeautifulSoup)
- [ ] 로고 이미지 추출 및 유사도 비교
- [ ] 페이지 제목 및 메타 태그 분석
- [ ] 숨겨진 iframe 탐지
- [ ] JavaScript 난독화 탐지

### 캐싱 및 최적화
- [ ] 분석 결과 캐싱 (Redis 사용)
- [ ] TTL(Time To Live) 설정 (1시간)
- [ ] 캐시 무효화 로직
- [ ] 병렬 분석 구현 (Promise.all)

### 테스트
- [ ] 알려진 피싱 사이트 탐지 테스트
- [ ] 정상 사이트 false positive 테스트
- [ ] Typosquatting 탐지 테스트
- [ ] SSL 인증서 검증 테스트
- [ ] 외부 API 실패 시 fallback 테스트

---

## 4. Risk Assessment Engine (위험도 평가 엔진)

### 점수 산정 시스템
- [ ] 각 지표별 가중치 정의
- [ ] 점수 합산 함수 구현
- [ ] 위험도 등급 분류 로직 (상/중/하)
- [ ] 점수 임계값 설정 (상: 70+, 중: 40-69, 하: 0-39)

### 판단 근거 생성
- [ ] 탐지된 위험 요소 목록 생성
- [ ] 사용자 친화적인 메시지 변환
- [ ] 다국어 지원 (한국어/영어)

### 동적 임계값 조정
- [ ] 사용자 피드백 기반 임계값 조정
- [ ] False positive/negative 비율 추적
- [ ] 머신러닝 기반 점수 조정 (선택사항)

### 화이트리스트 관리
- [ ] 화이트리스트 DB 구축
- [ ] 화이트리스트 자동 검증 로직
- [ ] 대형 서비스 도메인 사전 등록 (google.com, facebook.com 등)

### 테스트
- [ ] 점수 계산 정확도 테스트
- [ ] 경계값 테스트 (70점, 40점 근처)
- [ ] 화이트리스트 우선순위 테스트
- [ ] 다양한 피싱 시나리오 테스트

---

## 5. Response Handler (응답 처리 모듈)

### 응답 생성
- [ ] 위험도별 응답 분기 로직
- [ ] 정상 응답 통과 함수
- [ ] 경고 메시지 생성 함수 (위험도 중)
- [ ] 차단 응답 생성 함수 (위험도 상)

### 경고 페이지 HTML
- [ ] 경고 페이지 HTML 템플릿 작성
- [ ] 위험 요소 상세 표시
- [ ] 안전한 대체 경로 안내
- [ ] 사용자 신고 기능 추가
- [ ] "계속 진행" 버튼 구현 (위험도 중)

### 로깅
- [ ] 차단된 요청 로그 기록
- [ ] 분석 결과 로그 저장
- [ ] 개인정보 마스킹 (credential 제거)
- [ ] 로그 로테이션 설정

### 테스트
- [ ] 각 위험도별 응답 테스트
- [ ] 경고 페이지 렌더링 테스트
- [ ] 로그 기록 정확성 테스트

---

## 6. Database & Storage (데이터베이스 및 저장소)

### Redis 설정
- [ ] Redis 연결 설정
- [ ] 캐싱 키 네이밍 규칙 정의
- [ ] TTL 설정
- [ ] Redis 에러 핸들링

### MariaDB 설정
- [ ] 데이터베이스 스키마 설계
- [ ] 블랙리스트 테이블 생성
- [ ] 화이트리스트 테이블 생성
- [ ] 분석 로그 테이블 생성
- [ ] 사용자 신고 테이블 생성
- [ ] 인덱스 설정 (URL, 도메인, 타임스탬프)

### 마이그레이션
- [ ] 데이터베이스 마이그레이션 스크립트 작성
- [ ] 초기 데이터 시딩 (화이트리스트)

### 데이터 보관 정책
- [ ] 로그 자동 삭제 스케줄러 (30일 후)
- [ ] GDPR 준수 개인정보 삭제 로직

### 테스트
- [ ] 데이터베이스 CRUD 테스트
- [ ] 캐시 hit/miss 테스트
- [ ] 마이그레이션 테스트

---

## 7. API Server (API 서버)

### 엔드포인트 구현
- [ ] POST /api/v1/analyze - 요청 분석
- [ ] GET /api/v1/status/:id - 분석 상태 조회
- [ ] POST /api/v1/report - 피싱 사이트 신고
- [ ] GET /api/v1/blacklist - 블랙리스트 조회 (관리자)
- [ ] POST /api/v1/blacklist - 블랙리스트 추가 (관리자)
- [ ] GET /api/v1/whitelist - 화이트리스트 조회 (관리자)
- [ ] POST /api/v1/whitelist - 화이트리스트 추가 (관리자)
- [ ] GET /api/v1/health - 헬스 체크

### 인증 및 권한
- [ ] API 키 인증 시스템
- [ ] JWT 토큰 발급
- [ ] 관리자 권한 검증 미들웨어
- [ ] Rate limiting 미들웨어

### 입력 검증
- [ ] 요청 바디 스키마 검증 (Joi, Zod, Pydantic)
- [ ] URL 형식 검증
- [ ] SQL Injection 방어
- [ ] XSS 방어

### API 문서
- [ ] Swagger/OpenAPI 스펙 작성
- [ ] API 문서 자동 생성 설정
- [ ] 예시 요청/응답 추가

### 테스트
- [ ] 각 엔드포인트 통합 테스트
- [ ] 인증/권한 테스트
- [ ] 에러 응답 테스트 (400, 401, 403, 404, 500)
- [ ] Rate limiting 테스트

---

## 8. Frontend - Warning Page (경고 페이지)

### HTML/CSS 구현
- [ ] 경고 페이지 레이아웃 디자인
- [ ] 위험도별 색상 코드 (빨강, 주황, 초록)
- [ ] 반응형 디자인 (모바일 대응)
- [ ] 다크모드 지원 (선택사항)

### JavaScript 기능
- [ ] "계속 진행" 버튼 동작
- [ ] "안전한 페이지로 돌아가기" 버튼
- [ ] 피싱 사이트 신고 폼
- [ ] 애니메이션 효과

### 다국어 지원
- [ ] 한국어 템플릿
- [ ] 영어 템플릿
- [ ] 언어 자동 감지 또는 설정

### 테스트
- [ ] 브라우저 호환성 테스트 (Chrome, Firefox, Safari)
- [ ] 모바일 디바이스 테스트
- [ ] 접근성 테스트 (WCAG 준수)

---

## 9. Logging & Monitoring (로깅 및 모니터링)

### 로깅 시스템
- [ ] 구조화된 로그 포맷 정의 (JSON)
- [ ] 로그 레벨 설정 (DEBUG, INFO, WARN, ERROR)
- [ ] 민감정보 마스킹 함수
- [ ] 로그 파일 로테이션 설정
- [ ] 중앙 로그 수집 시스템 연동 (ELK, Datadog 등)

### 메트릭 수집
- [ ] 요청 처리 시간 측정
- [ ] 탐지율 추적
- [ ] False positive/negative 비율
- [ ] 외부 API 응답 시간
- [ ] 에러 발생 빈도

### 모니터링 대시보드
- [ ] Prometheus 메트릭 수집
- [ ] Grafana 대시보드 구성
- [ ] 알림 설정 (에러율 임계값 초과 시)

### 테스트
- [ ] 로그 포맷 검증 테스트
- [ ] 민감정보 마스킹 테스트
- [ ] 메트릭 수집 정확도 테스트

---

## 10. Security & Privacy (보안 및 개인정보 보호)

### 보안 강화
- [ ] HTTPS 강제 적용
- [ ] CORS 정책 설정
- [ ] Helmet.js 또는 보안 헤더 설정
- [ ] SQL Injection 방어 검증
- [ ] XSS 방어 검증
- [ ] CSRF 토큰 구현
- [ ] 비밀 키 및 토큰 암호화 저장 (환경 변수)

### 개인정보 보호
- [ ] credential 로그 기록 금지 검증
- [ ] 개인식별정보(PII) 마스킹
- [ ] 데이터 보관 기간 준수 (30일)
- [ ] 자동 삭제 스크립트
- [ ] GDPR 준수 개인정보 처리 방침 작성

### 보안 감사
- [ ] 의존성 취약점 스캔 (npm audit, safety)
- [ ] 코드 정적 분석 (SonarQube, Bandit)
- [ ] 침투 테스트 수행

### 테스트
- [ ] 보안 헤더 검증 테스트
- [ ] 인증/인가 우회 시도 테스트
- [ ] SQL Injection 시도 테스트
- [ ] XSS 시도 테스트

---

## 11. Testing (테스트)

### 단위 테스트
- [ ] Request Interceptor 테스트
- [ ] Login Detector 테스트
- [ ] Phishing Analyzer 테스트
- [ ] Risk Engine 테스트
- [ ] Response Handler 테스트
- [ ] 커버리지 80% 이상 달성

### 통합 테스트
- [ ] 전체 파이프라인 흐름 테스트
- [ ] 데이터베이스 연동 테스트
- [ ] 외부 API 모킹 및 테스트

### E2E 테스트
- [ ] 실제 피싱 사이트 탐지 시나리오
- [ ] 정상 사이트 통과 시나리오
- [ ] 경고 페이지 표시 시나리오

### 성능 테스트
- [ ] 부하 테스트 (Artillery, Locust)
- [ ] 동시 요청 처리 테스트
- [ ] 응답 시간 측정 (목표: 3초 이내)

### 테스트 자동화
- [ ] CI/CD 파이프라인에 테스트 통합
- [ ] Pre-commit hook 설정
- [ ] 테스트 리포트 자동 생성

---

## 12. Documentation (문서화)

### 코드 문서
- [ ] JSDoc 또는 docstring 주석 추가
- [ ] 복잡한 로직에 대한 설명 주석
- [ ] 함수 시그니처 명확화

### API 문서
- [ ] Swagger/OpenAPI 완성
- [ ] Postman Collection 작성
- [ ] 예제 cURL 커맨드 추가

### 사용자 문서
- [ ] 설치 가이드 작성
- [ ] 설정 가이드 작성
- [ ] 트러블슈팅 가이드 작성
- [ ] FAQ 작성

### 개발자 문서
- [ ] 아키텍처 다이어그램 작성
- [ ] 데이터 플로우 다이어그램
- [ ] 기여 가이드라인 작성

---

## 13. Deployment & DevOps (배포 및 데브옵스)

### 컨테이너화
- [ ] Dockerfile 작성
- [ ] docker-compose.yml 작성 (개발 환경)
- [ ] 멀티 스테이지 빌드 최적화
- [ ] 이미지 크기 최소화

### CI/CD 파이프라인
- [ ] GitHub Actions 또는 GitLab CI 설정
- [ ] 자동 테스트 실행
- [ ] 자동 빌드
- [ ] 자동 배포 (스테이징/프로덕션)
- [ ] 롤백 전략 수립

### 인프라 구성
- [ ] 클라우드 플랫폼 선택 (AWS, GCP, Azure)
- [ ] 로드 밸런서 설정
- [ ] Auto-scaling 설정
- [ ] CDN 설정 (정적 리소스)
- [ ] 백업 및 복구 전략

### 환경 관리
- [ ] 개발 환경 설정
- [ ] 스테이징 환경 설정
- [ ] 프로덕션 환경 설정
- [ ] 환경별 환경 변수 관리

### 모니터링 및 알림
- [ ] 헬스 체크 엔드포인트
- [ ] Uptime 모니터링 (UptimeRobot, Pingdom)
- [ ] 에러 추적 (Sentry, Rollbar)
- [ ] 알림 채널 설정 (Slack, 이메일)

### 테스트
- [ ] 스테이징 환경 배포 테스트
- [ ] 프로덕션 배포 시뮬레이션
- [ ] 롤백 테스트

---

## 14. Performance Optimization (성능 최적화)

### 캐싱 전략
- [ ] HTTP 캐싱 헤더 설정
- [ ] Redis 캐싱 최적화
- [ ] CDN 캐싱 설정

### 데이터베이스 최적화
- [ ] 쿼리 최적화
- [ ] 인덱스 최적화
- [ ] 커넥션 풀링 설정

### 비동기 처리
- [ ] 무거운 작업 백그라운드 큐로 이동 (Bull, Celery)
- [ ] 메시지 큐 도입 (RabbitMQ, Kafka)
- [ ] 이벤트 기반 아키텍처 고려

### 코드 최적화
- [ ] N+1 쿼리 제거
- [ ] 불필요한 API 호출 제거
- [ ] 병렬 처리 적용

---

## 15. Launch Preparation (출시 준비)

### 법적 검토
- [ ] 이용약관 작성
- [ ] 개인정보 처리방침 작성
- [ ] 쿠키 정책 작성
- [ ] 법률 자문 검토

### 마케팅 자료
- [ ] 랜딩 페이지 제작
- [ ] 데모 비디오 제작
- [ ] 기술 블로그 포스트 작성
- [ ] 프레스 릴리스 준비

### 출시 체크리스트
- [ ] 모든 테스트 통과 확인
- [ ] 보안 감사 완료
- [ ] 성능 벤치마크 목표 달성
- [ ] 문서화 완료
- [ ] 백업 시스템 가동
- [ ] 모니터링 대시보드 확인
- [ ] 알림 시스템 테스트
- [ ] 고객 지원 채널 준비

### 소프트 런치
- [ ] 베타 테스터 모집
- [ ] 피드백 수집
- [ ] 버그 수정
- [ ] 공식 출시

---

## 16. Post-Launch (출시 후)

### 유지보수
- [ ] 버그 리포트 모니터링
- [ ] 긴급 패치 대응 프로세스
- [ ] 정기 보안 업데이트

### 개선 사항
- [ ] 사용자 피드백 분석
- [ ] False positive 비율 개선
- [ ] 새로운 피싱 패턴 학습
- [ ] 외부 데이터 소스 추가

### 기능 확장
- [ ] 브라우저 확장 프로그램 개발
- [ ] 모바일 앱 개발
- [ ] 엔터프라이즈 기능 추가
- [ ] 머신러닝 모델 도입

---

## 우선순위 가이드

### Phase 1 (MVP - 최소 기능 제품)
1. Request Interceptor
2. Login Behavior Detector
3. Phishing Site Analyzer (기본)
4. Risk Assessment Engine (기본)
5. Response Handler
6. API Server (기본)

### Phase 2 (고도화)
1. 외부 API 연동 (Google Safe Browsing 등)
2. 데이터베이스 및 캐싱
3. 경고 페이지 고도화
4. 관리자 API
5. 모니터링 시스템

### Phase 3 (프로덕션 준비)
1. 보안 강화
2. 성능 최적화
3. 완전한 테스트 커버리지
4. CI/CD 파이프라인
5. 문서화 완료

---

**마지막 업데이트**: 2026-02-03
**진행률**: 0% (0/300+ 항목 완료)
