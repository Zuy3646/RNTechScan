"""
Базовый интерфейс плагинов для модулей сканера уязвимостей.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import time


class SeverityLevel(Enum):
    """Уровни критичности уязвимостей."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


from dataclasses import asdict

@dataclass
class Vulnerability:
    """Представляет обнаруженную уязвимость."""
    id: str
    name: str
    description: str
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: Optional[str] = None
    solution: Optional[str] = None
    references: Optional[List[str]] = None
    timestamp: Optional[float] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.references is None:
            self.references = []

    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать уязвимость в словарь."""
        return asdict(self)


@dataclass
class ScanTarget:
    """Представляет цель сканирования."""
    host: str
    ports: Optional[List[int]] = None
    services: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.services is None:
            self.services = []
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать цель в словарь."""
        return asdict(self)


class ScanResult:
    """Содержит результаты операции сканирования."""
    
    def __init__(self, target: ScanTarget, plugin_name: str):
        self.target = target
        self.plugin_name = plugin_name
        self.vulnerabilities: List[Vulnerability] = []
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.status = "running"
        self.error: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Добавить уязвимость в результаты."""
        self.vulnerabilities.append(vulnerability)
    
    def finish(self, status: str = "completed", error: Optional[str] = None) -> None:
        """Отметить сканирование как завершённое."""
        self.end_time = time.time()
        self.status = status
        self.error = error
    
    @property
    def duration(self) -> Optional[float]:
        """Получить продолжительность сканирования в секундах."""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def vulnerability_count(self) -> int:
        """Получить общее количество найденных уязвимостей."""
        return len(self.vulnerabilities)
    
    def get_vulnerabilities_by_severity(self, severity: SeverityLevel) -> List[Vulnerability]:
        """Получить уязвимости, отфильтрованные по уровню опасности."""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать результат в словарь."""
        return {
            "target": self.target.to_dict(),
            "plugin_name": self.plugin_name,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "error": self.error,
            "metadata": self.metadata,
        }


class BasePlugin(ABC):
    """Базовый класс для всех плагинов сканера."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.enabled = config.get('enabled', True)
        self.timeout = config.get('timeout', 30)
    
    @abstractmethod
    def get_name(self) -> str:
        """Вернуть имя плагина."""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Вернуть описание плагина."""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Вернуть версию плагина."""
        pass
    
    @abstractmethod
    def is_applicable(self, target: ScanTarget) -> bool:
        """Проверить, применим ли этот плагин к данной цели."""
        pass
    
    @abstractmethod
    def scan(self, target: ScanTarget) -> ScanResult:
        """Выполнить фактическое сканирование и вернуть результаты."""
        pass
    
    def validate_config(self) -> bool:
        """Провалидировать конфигурацию плагина."""
        return True
    
    def cleanup(self) -> None:
        """Очистить ресурсы после сканирования."""
        pass
    
    def get_supported_services(self) -> List[str]:
        """Получить список сервисов, которые может сканировать этот плагин."""
        return []
    
    def get_required_ports(self) -> List[int]:
        """Получить список портов, которые должны быть открыты для этого плагина."""
        return []


class PluginManager:
    """Менеджер плагинов сканера."""
    
    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_order: List[str] = []
    
    def register_plugin(self, plugin: BasePlugin) -> None:
        """Зарегистрировать новый плагин."""
        if plugin.validate_config():
            self.plugins[plugin.get_name()] = plugin
            if plugin.get_name() not in self.plugin_order:
                self.plugin_order.append(plugin.get_name())
        else:
            raise ValueError(f"Plugin {plugin.get_name()} has invalid configuration")
    
    def unregister_plugin(self, plugin_name: str) -> None:
        """Отменить регистрацию плагина."""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].cleanup()
            del self.plugins[plugin_name]
            if plugin_name in self.plugin_order:
                self.plugin_order.remove(plugin_name)
    
    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Получить плагин по имени."""
        return self.plugins.get(plugin_name)
    
    def get_all_plugins(self) -> Dict[str, BasePlugin]:
        """Получить все зарегистрированные плагины."""
        return self.plugins.copy()
    
    def get_applicable_plugins(self, target: ScanTarget) -> List[BasePlugin]:
        """Получить плагины, применимые к данной цели."""
        applicable = []
        for plugin_name in self.plugin_order:
            plugin = self.plugins[plugin_name]
            if plugin.enabled and plugin.is_applicable(target):
                applicable.append(plugin)
        return applicable
    
    def get_plugins_by_service(self, service: str) -> List[BasePlugin]:
        """Получить плагины, которые могут сканировать конкретный сервис."""
        service_plugins = []
        for plugin in self.plugins.values():
            if plugin.enabled and service.lower() in [s.lower() for s in plugin.get_supported_services()]:
                service_plugins.append(plugin)
        return service_plugins
    
    def cleanup_all(self) -> None:
        """Очистить все зарегистрированные плагины."""
        for plugin in self.plugins.values():
            plugin.cleanup()