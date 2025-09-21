"""
Конфигурационные настройки для сканера уязвимостей.
"""
import os
import yaml
import json
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    """Основной класс конфигурации для сканера уязвимостей."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_data = {}
        self.default_config = self._get_default_config()
        
        if config_file:
            self.load_config(config_file)
        else:
            self.config_data = self.default_config.copy()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Получить конфигурацию по умолчанию."""
        return {
            "scanner": {
                "max_threads": 10,
                "timeout": 30,
                "delay_between_requests": 0.1,
                "user_agent": "RNTechScan/1.0",
                "max_retries": 3,
                "output_format": "json"
            },
            "modules": {
                "network": {
                    "enabled": True,
                    "port_scan_range": "1-1000",
                    "scan_type": "tcp"
                },
                "web": {
                    "enabled": True,
                    "follow_redirects": True,
                    "verify_ssl": False,
                    "max_page_depth": 3
                },
                "system": {
                    "enabled": True,
                    "check_services": True,
                    "check_files": True,
                    "check_permissions": True
                }
            },
            "reporting": {
                "output_dir": "reports",
                "format": ["json", "html"],
                "include_details": True,
                "severity_levels": ["critical", "high", "medium", "low", "info"]
            },
            "logging": {
                "level": "INFO",
                "file": "scanner.log",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        }
    
    def load_config(self, config_file: str) -> None:
        """Загрузить конфигурацию из файла (YAML или JSON)."""
        config_path = Path(config_file)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Конфигурационный файл не найден: {config_file}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                if config_path.suffix.lower() in ['.yml', '.yaml']:
                    loaded_config = yaml.safe_load(f)
                elif config_path.suffix.lower() == '.json':
                    loaded_config = json.load(f)
                else:
                    raise ValueError(f"Неподдерживаемый формат конфигурации: {config_path.suffix}")
            
            # Объединить с конфигурацией по умолчанию
            self.config_data = self._merge_config(self.default_config, loaded_config)
            
        except Exception as e:
            raise RuntimeError(f"Ошибка загрузки конфигурации: {e}")
    
    def _merge_config(self, default: Dict[str, Any], custom: Dict[str, Any]) -> Dict[str, Any]:
        """Рекурсивно объединить пользовательскую конфигурацию с конфигурацией по умолчанию."""
        result = default.copy()
        
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """Получить значение конфигурации с использованием точечной нотации (например, 'scanner.timeout')."""
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Установить значение конфигурации с использованием точечной нотации."""
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save_config(self, config_file: str) -> None:
        """Сохранить текущую конфигурацию в файл."""
        config_path = Path(config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                if config_path.suffix.lower() in ['.yml', '.yaml']:
                    yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
                elif config_path.suffix.lower() == '.json':
                    json.dump(self.config_data, f, indent=2, ensure_ascii=False)
                else:
                    raise ValueError(f"Неподдерживаемый формат конфигурации: {config_path.suffix}")
        except Exception as e:
            raise RuntimeError(f"Ошибка сохранения конфигурации: {e}")
    
    def validate(self) -> bool:
        """Проверить настройки конфигурации."""
        errors = []
        
        # Проверить настройки сканера
        if self.get('scanner.max_threads', 0) <= 0:
            errors.append("scanner.max_threads must be greater than 0")
        
        if self.get('scanner.timeout', 0) <= 0:
            errors.append("scanner.timeout must be greater than 0")
        
        # Проверить директорию вывода
        output_dir = self.get('reporting.output_dir')
        if output_dir:
            try:
                Path(output_dir).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create output directory {output_dir}: {e}")
        
        if errors:
            raise ValueError("Configuration validation errors: " + "; ".join(errors))
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Вернуть конфигурацию в виде словаря."""
        return self.config_data.copy()


# Глобальный экземпляр конфигурации
config = Config()


def get_config() -> Config:
    """Получить глобальный экземпляр конфигурации."""
    return config


def load_config_file(config_file: str) -> None:
    """Загрузить конфигурацию из файла в глобальный экземпляр."""
    global config
    config.load_config(config_file)