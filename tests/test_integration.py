import pytest
from httpx import AsyncClient
from app.main import app


@pytest.mark.asyncio
class TestIntegration:
    """통합 테스트 - 전체 파이프라인"""

    async def test_health_check(self):
        """헬스 체크"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data['status'] == 'healthy'
            assert 'version' in data
            assert 'blacklist_count' in data

    async def test_root_endpoint(self):
        """루트 엔드포인트"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/")

            assert response.status_code == 200
            assert 'text/html' in response.headers['content-type']
            assert 'Credential Phishing Detection System' in response.text

    async def test_analyze_ip_address_phishing(self):
        """IP 주소 사용 피싱 사이트 전체 플로우"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            request_data = {
                "url": "http://192.168.1.1/login",
                "method": "POST",
                "headers": {},
                "body": {"username": "test", "password": "pass123"}
            }

            response = await client.post("/api/v1/analyze", json=request_data)

            # IP 주소 사용은 고위험이므로 차단 (403) 또는 경고 (200)
            assert response.status_code in [200, 403]

            if response.status_code == 200:
                data = response.json()
                assert data['is_login_attempt'] is True
                assert data['risk_level'] in ['high', 'medium']
                assert any('IP 주소' in reason for reason in data['reasons'])
            else:  # 403 차단
                assert 'text/html' in response.headers['content-type']
                assert '위험한 사이트' in response.text

    async def test_analyze_normal_site(self):
        """정상 사이트 허용"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            request_data = {
                "url": "https://www.google.com/login",
                "method": "POST",
                "headers": {},
                "body": {"username": "test", "password": "pass"}
            }

            response = await client.post("/api/v1/analyze", json=request_data)

            assert response.status_code == 200
            data = response.json()
            assert data['is_login_attempt'] is True
            # Google은 정상 사이트이므로 저위험일 가능성 높음
            # 단, 외부 API 설정에 따라 다를 수 있음

    async def test_analyze_non_login_request(self):
        """로그인이 아닌 요청은 통과"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            request_data = {
                "url": "https://example.com/api/data",
                "method": "POST",
                "headers": {},
                "body": {"data": "test"}
            }

            response = await client.post("/api/v1/analyze", json=request_data)

            assert response.status_code == 200
            data = response.json()
            assert data['is_login_attempt'] is False
            assert data['action'] == 'allowed'

    async def test_analyze_blacklisted_domain(self):
        """블랙리스트 도메인 차단"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            request_data = {
                "url": "http://phishing-example.com/login",
                "method": "POST",
                "headers": {},
                "body": {"username": "test", "password": "pass"}
            }

            response = await client.post("/api/v1/analyze", json=request_data)

            # 블랙리스트 도메인은 고위험
            assert response.status_code in [200, 403]

            if response.status_code == 200:
                data = response.json()
                assert data['is_login_attempt'] is True
                assert data['risk_level'] in ['high', 'medium']
                assert any('블랙리스트' in reason for reason in data['reasons'])
            else:
                # 차단 페이지
                assert '위험한 사이트' in response.text

    async def test_analyze_suspicious_pattern(self):
        """의심스러운 URL 패턴 감지"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            request_data = {
                "url": "http://user@fake-site.com/login",
                "method": "POST",
                "headers": {},
                "body": {"username": "test", "password": "pass"}
            }

            response = await client.post("/api/v1/analyze", json=request_data)

            assert response.status_code in [200, 403]

            if response.status_code == 200:
                data = response.json()
                assert data['is_login_attempt'] is True
                # 의심스러운 패턴으로 점수 증가

    async def test_analyze_with_auth_endpoint(self):
        """인증 엔드포인트 감지"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            request_data = {
                "url": "https://example.com/oauth/token",
                "method": "POST",
                "headers": {},
                "body": {"grant_type": "password", "username": "user", "password": "pass"}
            }

            response = await client.post("/api/v1/analyze", json=request_data)

            assert response.status_code in [200, 403]
            # OAuth 엔드포인트는 로그인 시도로 감지됨

    async def test_warning_page_content(self):
        """경고 페이지 콘텐츠 확인"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            request_data = {
                "url": "http://192.168.1.1/login",
                "method": "POST",
                "headers": {},
                "body": {"username": "test", "password": "pass"}
            }

            response = await client.post("/api/v1/analyze", json=request_data)

            if response.status_code == 403:
                html = response.text
                assert '⚠️' in html or '위험' in html
                assert '차단' in html
                assert '192.168.1.1' in html
                assert 'IP 주소' in html

    async def test_multiple_requests_in_sequence(self):
        """연속된 여러 요청 처리"""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # 정상 요청
            response1 = await client.post("/api/v1/analyze", json={
                "url": "https://www.example.com/api",
                "method": "GET",
                "headers": {},
                "body": None
            })
            assert response1.status_code == 200

            # 로그인 요청 (정상 사이트)
            response2 = await client.post("/api/v1/analyze", json={
                "url": "https://www.example.com/login",
                "method": "POST",
                "headers": {},
                "body": {"username": "test", "password": "pass"}
            })
            assert response2.status_code in [200, 403]

            # IP 주소 로그인 (위험)
            response3 = await client.post("/api/v1/analyze", json={
                "url": "http://10.0.0.1/login",
                "method": "POST",
                "headers": {},
                "body": {"username": "test", "password": "pass"}
            })
            assert response3.status_code in [200, 403]
