from abc import ABC, abstractmethod
from typing import Dict, Any
import httpx
import time
from app.models.analysis_result import RiskLevel, ExternalAPIResult
from app.utils.logger import log


class ExternalAPIBase(ABC):
    """
    외부 API 추상 기본 클래스

    모든 외부 API 클래스는 이 클래스를 상속받아 구현합니다.
    공통 기능:
    - HTTP 요청 처리
    - 타임아웃 관리
    - 에러 처리
    - 응답 시간 측정
    """

    def __init__(self, api_key: str = "", timeout: int = 3):
        """
        Args:
            api_key: API 키 (필요한 경우)
            timeout: 요청 타임아웃 (초)
        """
        self.api_key = api_key
        self.timeout = timeout
        self.api_name = self.__class__.__name__

    @abstractmethod
    async def check_url(self, url: str) -> ExternalAPIResult:
        """
        URL 분석 (하위 클래스에서 구현 필수)

        Args:
            url: 분석할 URL

        Returns:
            ExternalAPIResult: 분석 결과
        """
        pass

    async def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        HTTP 요청 헬퍼 메서드

        Args:
            method: HTTP 메서드 (GET, POST 등)
            url: 요청 URL
            **kwargs: httpx 요청 파라미터 (headers, json, params 등)

        Returns:
            dict: 요청 결과
                - success: bool (성공 여부)
                - data: dict (응답 데이터, 성공 시)
                - status_code: int (HTTP 상태 코드, 성공 시)
                - response_time: float (응답 시간 ms, 성공 시)
                - error: str (에러 메시지, 실패 시)
        """
        start_time = time.time()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if method.upper() == 'GET':
                    response = await client.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = await client.post(url, **kwargs)
                else:
                    return {'success': False, 'error': f'Unsupported method: {method}'}

                response.raise_for_status()
                response_time = (time.time() - start_time) * 1000

                return {
                    'success': True,
                    'data': response.json() if response.content else {},
                    'status_code': response.status_code,
                    'response_time': response_time
                }

        except httpx.TimeoutException:
            log.warning(f"{self.api_name} timeout for URL: {url}")
            return {
                'success': False,
                'error': 'timeout',
                'response_time': self.timeout * 1000
            }

        except httpx.HTTPStatusError as e:
            log.warning(f"{self.api_name} HTTP error {e.response.status_code}: {url}")
            return {
                'success': False,
                'error': f'HTTP {e.response.status_code}',
                'response_time': (time.time() - start_time) * 1000
            }

        except Exception as e:
            log.error(f"{self.api_name} error: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'response_time': (time.time() - start_time) * 1000
            }

    def _create_error_result(self, error: str) -> ExternalAPIResult:
        """
        에러 결과 생성 헬퍼

        Args:
            error: 에러 메시지

        Returns:
            ExternalAPIResult: 에러 결과 (위협 없음으로 처리)
        """
        return ExternalAPIResult(
            api_name=self.api_name,
            is_threat=False,
            risk_level=RiskLevel.LOW,
            details={'error': error, 'checked': False},
            response_time_ms=0
        )
