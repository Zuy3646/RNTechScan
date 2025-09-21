"""
Конфигурация логирования для сканера уязвимостей.
"""
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
from .settings import get_config


def setup_logging(log_file: Optional[str] = None, log_level: Optional[str] = None) -> logging.Logger:
    """Настройка конфигурации логирования."""
    config = get_config()
    
    # Получить настройки логирования из конфигурации
    if not log_level:
        log_level = config.get('logging.level', 'INFO')
    
    if not log_file:
        log_file = config.get('logging.file', 'scanner.log')
    
    log_format = config.get('logging.format', 
                           '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Убедиться, что log_level является строкой
    if not isinstance(log_level, str):
        log_level = 'INFO'
    
    # Создать логгер
    logger = logging.getLogger('vuln_scanner')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Очистить существующие обработчики
    logger.handlers.clear()
    
    # Создать форматтер
    formatter = logging.Formatter(log_format)
    
    # Обработчик консоли
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Обработчик файла
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = 'vuln_scanner') -> logging.Logger:
    """Получить экземпляр логгера."""
    return logging.getLogger(name)