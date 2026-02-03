# Credential Phishing Detection System - 개발 착수 계획

> 작성일: 2026-02-03
> 기술 스택: Python + FastAPI
> 예상 기간: 7일 (MVP)

## 프로젝트 개요

HTTP 요청을 분석하여 credential phishing 공격을 탐지하고 차단하는 보안 시스템 구축

## 현재 상태
- 문서화 완료: README.md, claude.md, todo.md
- 소스 코드: 없음 (완전히 새로운 프로젝트)
- 개발 환경: 미구성

## 확정된 기술 스택

### 백엔드: Python + FastAPI
**선택 이유:**
- 풍부한 보안/데이터 분석 라이브러리
- 향후 머신러닝 기반 탐지 확장 용이
- FastAPI의 우수한 비동기 처리 성능
- Pydantic을 통한 강력한 데이터 검증
- 자동 API 문서 생성 (OpenAPI/Swagger)

**주요 프레임워크 및 라이브러리:**
- FastAPI: 웹 프레임워크
- Uvicorn: ASGI 서버
- httpx: 비동기 HTTP 클라이언트
- BeautifulSoup4: HTML 파싱
- python-Levenshtein: 문자열 유사도
- validators: URL 검증
- python-dotenv: 환경 변수 관리

## MVP (Phase 1) 개발 계획

### 목표
최소 기능으로 동작하는 피싱 탐지 시스템 구축
- 로그인 요청 감지
- 기본 피싱 사이트 분석
- 외부 API 다중 선택 지원 (옵션)
- 위험도 평가 및 경고 페이지 표시

### 타임라인 (7일)

| 일차 | 단계 | 주요 작업 |
|------|------|----------|
| **Day 1** | 프로젝트 초기 설정 | 디렉토리 구조, 의존성 설치, 환경 변수 |
| **Day 2** | 데이터 모델 및 설정 | Pydantic 모델, 설정 관리, 로거 |
| **Day 3** | 로그인 감지 및 기본 분석 | LoginDetector, DomainAnalyzer, Blacklist |
| **Day 4** | 외부 API 연동 | 추상 클래스, Google/VirusTotal API, 병렬 호출 |
| **Day 5** | 위험도 평가 엔진 | RiskCalculator, 내부+외부 통합 로직 |
| **Day 6** | 전체 통합 및 API | PhishingAnalyzer, FastAPI 엔드포인트 |
| **Day 7** | 테스트 및 검증 | 단위/통합 테스트, 버그 수정 |

## 핵심 기능

### 1. 로그인 행위 탐지
POST + credential 패턴 분석으로 로그인 시도 자동 감지

### 2. 내부 피싱 분석
- 블랙리스트 확인
- IP 주소 직접 사용 탐지
- 의심스러운 URL 패턴

### 3. 외부 API 다중 선택 (핵심 기능)
**기본값: 미사용**
- 환경 변수로 개별 활성화/비활성화
- Google Safe Browsing, VirusTotal 등 다중 선택 가능
- **병렬 호출**: asyncio.gather로 성능 최적화
- **최고 위험도 선택**: 여러 API 중 가장 높은 위험도 채택
- **상세 로깅**: 각 API의 개별 결과를 로그에 기록

### 4. 위험도 3단계 평가
- **상 (HIGH)**: 접근 차단 및 경고 페이지
- **중 (MEDIUM)**: 경고 메시지
- **하 (LOW)**: 정상 통과

## 프로젝트 구조

```
my_project/
├── app/
│   ├── main.py               # FastAPI 메인
│   ├── config.py             # 설정 관리
│   ├── detector/             # 로그인 탐지
│   ├── analyzer/             # 피싱 분석
│   │   └── external_api/     # 외부 API 연동
│   ├── risk_engine/          # 위험도 평가
│   ├── handler/              # 응답 처리
│   ├── models/               # Pydantic 모델
│   └── utils/                # 유틸리티
├── tests/                    # 테스트
├── static/                   # 정적 파일
├── data/                     # 블랙리스트 등
├── logs/                     # 로그
└── requirements.txt
```

## 외부 API 사용 시나리오

### 시나리오 1: 외부 API 미사용 (기본)
```bash
ENABLE_EXTERNAL_API=False
```
- 내부 분석만 사용
- 빠른 응답 시간
- 외부 의존성 없음

### 시나리오 2: Google Safe Browsing만 사용
```bash
ENABLE_EXTERNAL_API=True
USE_GOOGLE_SAFE_BROWSING=True
GOOGLE_SAFE_BROWSING_API_KEY=your_key
```

### 시나리오 3: 다중 API 사용 (권장)
```bash
ENABLE_EXTERNAL_API=True
USE_GOOGLE_SAFE_BROWSING=True
GOOGLE_SAFE_BROWSING_API_KEY=your_key
USE_VIRUSTOTAL=True
VIRUSTOTAL_API_KEY=your_key
```
- 모든 API에 병렬 요청
- 가장 높은 위험도 채택
- 각 API 결과를 로그에 기록

**로그 출력 예시:**
```
2026-02-03 14:30:15 | INFO | 외부 API 2개에 병렬 요청: http://phishing-site.com
2026-02-03 14:30:15 | INFO | Google Safe Browsing: threat=True, risk=high, time=234ms
2026-02-03 14:30:15 | INFO | VirusTotal: threat=True, risk=high, time=456ms
2026-02-03 14:30:15 | INFO | 외부 API 위험도가 더 높음: high > medium (source: Google Safe Browsing)
2026-02-03 14:30:15 | INFO | 분석 완료 - 위험도: high, 액션: blocked, 결정 소스: Google Safe Browsing
```

## 구현 우선순위

### Must Have (필수)
1. Login Detector: 로그인 시도 판단
2. Basic Analyzer: 블랙리스트, URL 패턴
3. Risk Engine: 위험도 계산
4. Response Handler: 경고 페이지
5. API Server: 기본 엔드포인트

### Should Have (Phase 2)
1. Redis 캐싱
2. MariaDB 로그 저장
3. SSL 인증서 검증
4. WHOIS 조회
5. 도메인 유사도 검사

### Could Have (Phase 3)
1. 페이지 콘텐츠 분석
2. 관리자 대시보드
3. 모니터링 시스템
4. 머신러닝 기반 탐지

## 핵심 구현 로직

### 1. 외부 API 다중 선택
```python
# 설정된 API만 초기화
apis = []
if settings.use_google_safe_browsing:
    apis.append(GoogleSafeBrowsingAPI())
if settings.use_virustotal:
    apis.append(VirusTotalAPI())

# 병렬 호출
results = await asyncio.gather(*[api.check_url(url) for api in apis])

# 가장 높은 위험도 선택
highest_risk = max(results, key=lambda r: risk_priority[r.risk_level])
```

### 2. 위험도 결정 우선순위
```
외부 API (HIGH) > 내부 분석 (HIGH) > 외부 API (MEDIUM) > 내부 분석 (MEDIUM) > LOW
```

### 3. 로그 기록 정책
- credential 정보는 절대 기록 안함 (마스킹)
- 각 외부 API의 개별 결과 기록
- 최종 결정 근거 명시 (internal or API 이름)
- 응답 시간 기록 (성능 모니터링)

## 개발 환경 설정

### 1. 가상환경 생성
```bash
python -m venv venv
venv\Scripts\activate  # Windows
```

### 2. 의존성 설치
```bash
pip install -r requirements.txt
```

### 3. 환경 변수 설정
```bash
cp .env.example .env
# .env 파일 편집
```

### 4. 서버 실행
```bash
uvicorn app.main:app --reload --port 8080
```

### 5. API 문서 확인
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc

## 테스트 전략

### 단위 테스트 (pytest)
```bash
pytest tests/test_detector.py
pytest tests/test_analyzer.py
pytest tests/test_risk_engine.py
```

### 통합 테스트
```bash
pytest tests/test_integration.py
```

### 커버리지
```bash
pytest --cov=app --cov-report=html
```

## 검증 체크리스트

- [ ] 로그인 요청이 정확히 감지되는가?
- [ ] IP 주소 사용 시 고위험으로 판단되는가?
- [ ] 블랙리스트 사이트가 차단되는가?
- [ ] 정상 사이트는 통과되는가?
- [ ] 외부 API가 설정대로 호출되는가?
- [ ] 다중 API 사용 시 병렬로 호출되는가?
- [ ] 가장 높은 위험도가 최종 결과로 선택되는가?
- [ ] 각 API 결과가 로그에 기록되는가?
- [ ] 경고 페이지가 올바르게 표시되는가?
- [ ] credential이 로그에 노출되지 않는가?

## 보안 고려사항

- credential은 절대 로그에 기록하지 않음
- 모든 외부 입력 검증 및 sanitization
- HTTPS 강제 사용
- 환경 변수로 민감 정보 관리
- SQL Injection, XSS 방어

## 예상 이슈 및 대응

### 1. False Positive (오탐)
- 문제: 정상 사이트를 피싱으로 오판
- 대응: 화이트리스트 관리, 임계값 조정

### 2. 성능 문제
- 문제: 분석 시간이 너무 오래 걸림
- 대응: 타임아웃 설정 (3초), 캐싱 도입

### 3. credential 로그 노출
- 문제: 보안상 민감한 정보 로깅
- 대응: 로깅 시 민감 정보 마스킹 필수

## 다음 단계 (Phase 2)

MVP 완성 후 추가할 기능:
1. **Redis 캐싱**: 반복 분석 방지, 성능 향상
2. **MariaDB 연동**: 로그, 블랙리스트, 화이트리스트 영구 저장
3. **SSL 인증서 검증**: 인증서 만료, 자체 서명 탐지
4. **WHOIS 조회**: 도메인 등록일, 등록자 정보
5. **도메인 유사도 검사**: Typosquatting 탐지
6. **페이지 콘텐츠 분석**: 로고 유사도, DOM 구조
7. **관리자 API**: 블랙리스트/화이트리스트 CRUD
8. **모니터링 대시보드**: Grafana + Prometheus
9. **머신러닝**: 피싱 패턴 학습 및 예측

## 결론

이 계획은 **Python + FastAPI** 기반으로 MVP를 구축하며, 다음 핵심 기능을 포함합니다:

1. **로그인 행위 탐지**: POST + credential 패턴 분석
2. **내부 피싱 분석**: 블랙리스트, IP 주소, URL 패턴
3. **외부 API 옵션 지원**:
   - 기본값: 미사용 (빠른 개발)
   - 다중 API 선택 가능 (Google, VirusTotal 등)
   - 병렬 호출 및 최고 위험도 선택
4. **위험도 3단계 평가**: 상/중/하
5. **차단 및 경고**: 위험도에 따른 응답

**외부 API의 핵심 특징:**
- 환경 변수로 개별 활성화/비활성화
- 다중 선택 시 병렬 호출 (성능 최적화)
- 가장 높은 위험도를 최종 결과로 선택
- 각 API 결과를 상세 로그에 기록

**개발 기간: 7일**로 MVP 완성 가능하며, 실제 테스트를 통해 검증 후 Phase 2로 확장할 수 있습니다.

---

## 참고 문서

- [README.md](./ReadMe.md): 프로젝트 개요 및 사용 방법
- [claude.md](./claude.md): 개발 가이드 및 기술 상세
- [todo.md](./todo.md): 전체 개발 체크리스트 (300+ 항목)
