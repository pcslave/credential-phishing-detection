from loguru import logger
import sys
import re
from pathlib import Path


def mask_sensitive_info(record):
    """
    로그 메시지에서 민감정보 마스킹
    password, passwd, pwd, token, api_key 등의 값을 ***로 대체
    """
    message = record["message"]

    # 민감한 키워드 패턴
    sensitive_patterns = [
        (r'("password"\s*:\s*)"[^"]*"', r'\1"***"'),  # JSON: "password": "value"
        (r'("passwd"\s*:\s*)"[^"]*"', r'\1"***"'),
        (r'("pwd"\s*:\s*)"[^"]*"', r'\1"***"'),
        (r'("token"\s*:\s*)"[^"]*"', r'\1"***"'),
        (r'("api_key"\s*:\s*)"[^"]*"', r'\1"***"'),
        (r'("secret"\s*:\s*)"[^"]*"', r'\1"***"'),
        (r'(password=)[^&\s]*', r'\1***'),  # URL query: password=value
        (r'(passwd=)[^&\s]*', r'\1***'),
        (r'(pwd=)[^&\s]*', r'\1***'),
        (r'(token=)[^&\s]*', r'\1***'),
    ]

    for pattern, replacement in sensitive_patterns:
        message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)

    record["message"] = message
    return True


def setup_logger(log_level: str = "INFO"):
    """
    로거 초기화 및 설정
    - 콘솔 출력 (색상 포맷)
    - 파일 출력 (일별 로테이션, 30일 보관)
    - 민감정보 자동 마스킹
    """
    # 기존 핸들러 제거
    logger.remove()

    # 콘솔 핸들러 추가
    logger.add(
        sys.stdout,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
               "<level>{message}</level>",
        filter=mask_sensitive_info,
        colorize=True
    )

    # 로그 디렉토리 생성
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # 파일 핸들러 추가 (일별 로테이션)
    logger.add(
        log_dir / "app_{time:YYYY-MM-DD}.log",
        rotation="00:00",  # 자정에 로테이션
        retention="30 days",  # 30일간 보관
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        filter=mask_sensitive_info,
        encoding="utf-8"
    )

    # 에러 로그 별도 파일
    logger.add(
        log_dir / "error_{time:YYYY-MM-DD}.log",
        rotation="00:00",
        retention="30 days",
        level="ERROR",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        filter=mask_sensitive_info,
        encoding="utf-8"
    )

    logger.info(f"Logger initialized with level: {log_level}")
    return logger


# 기본 로거 인스턴스 (나중에 config.py에서 설정된 레벨로 재초기화 가능)
log = setup_logger()
