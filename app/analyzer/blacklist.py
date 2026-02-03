import json
from pathlib import Path
from typing import Set, Optional
from app.utils.logger import log


class BlacklistManager:
    """
    블랙리스트 관리 클래스

    JSON 파일 기반으로 알려진 피싱 도메인 블랙리스트를 관리합니다.
    - 블랙리스트 로드 및 저장
    - 도메인 조회
    - 도메인 추가/제거
    """

    def __init__(self, blacklist_file: str = "data/blacklist.json"):
        """
        Args:
            blacklist_file: 블랙리스트 JSON 파일 경로
        """
        self.blacklist_file = Path(blacklist_file)
        self.blacklist: Set[str] = set()
        self.description: str = ""
        self._load_blacklist()

    def _load_blacklist(self):
        """블랙리스트 파일 로드"""
        if not self.blacklist_file.exists():
            log.warning(f"블랙리스트 파일 없음: {self.blacklist_file}")
            self._create_default_blacklist()
            return

        try:
            with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.blacklist = set(domain.lower() for domain in data.get('domains', []))
                self.description = data.get('description', '')
                log.info(f"블랙리스트 로드 완료: {len(self.blacklist)}개 도메인")
        except json.JSONDecodeError as e:
            log.error(f"블랙리스트 JSON 파싱 실패: {e}")
            self.blacklist = set()
        except Exception as e:
            log.error(f"블랙리스트 로드 실패: {e}")
            self.blacklist = set()

    def _create_default_blacklist(self):
        """기본 블랙리스트 생성"""
        self.blacklist_file.parent.mkdir(parents=True, exist_ok=True)

        default_data = {
            "domains": [
                "phishing-example.com",
                "fake-login.net",
                "suspicious-site.org"
            ],
            "description": "Known phishing domains - Please add suspicious domains here"
        }

        try:
            with open(self.blacklist_file, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, indent=2, ensure_ascii=False)
            self.blacklist = set(domain.lower() for domain in default_data['domains'])
            self.description = default_data['description']
            log.info(f"기본 블랙리스트 생성 완료: {self.blacklist_file}")
        except Exception as e:
            log.error(f"기본 블랙리스트 생성 실패: {e}")

    def is_blacklisted(self, domain: str) -> bool:
        """
        도메인이 블랙리스트에 있는지 확인

        Args:
            domain: 확인할 도메인

        Returns:
            bool: 블랙리스트 포함 여부
        """
        if not domain:
            return False
        return domain.lower() in self.blacklist

    def add(self, domain: str) -> bool:
        """
        블랙리스트에 도메인 추가

        Args:
            domain: 추가할 도메인

        Returns:
            bool: 추가 성공 여부
        """
        if not domain:
            return False

        domain = domain.lower()
        if domain in self.blacklist:
            log.warning(f"이미 블랙리스트에 존재: {domain}")
            return False

        self.blacklist.add(domain)
        self._save_blacklist()
        log.info(f"블랙리스트에 추가: {domain}")
        return True

    def remove(self, domain: str) -> bool:
        """
        블랙리스트에서 도메인 제거

        Args:
            domain: 제거할 도메인

        Returns:
            bool: 제거 성공 여부
        """
        if not domain:
            return False

        domain = domain.lower()
        if domain not in self.blacklist:
            log.warning(f"블랙리스트에 없음: {domain}")
            return False

        self.blacklist.remove(domain)
        self._save_blacklist()
        log.info(f"블랙리스트에서 제거: {domain}")
        return True

    def _save_blacklist(self):
        """블랙리스트 파일에 저장"""
        try:
            data = {
                'domains': sorted(list(self.blacklist)),
                'description': self.description or "Known phishing domains"
            }
            with open(self.blacklist_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            log.debug(f"블랙리스트 저장 완료: {len(self.blacklist)}개 도메인")
        except Exception as e:
            log.error(f"블랙리스트 저장 실패: {e}")

    def get_count(self) -> int:
        """블랙리스트 도메인 개수 반환"""
        return len(self.blacklist)

    def get_all(self) -> Set[str]:
        """블랙리스트 전체 목록 반환"""
        return self.blacklist.copy()

    def reload(self):
        """블랙리스트 다시 로드"""
        self._load_blacklist()
