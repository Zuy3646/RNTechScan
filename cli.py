"""
Интерфейс командной строки для сканера уязвимостей.
"""
import argparse
import sys
import os
import signal
from typing import List, Optional, Dict, Any
from pathlib import Path

from core.scanner import ScanEngine
from core.plugin_base import ScanTarget
from modules.network.port_scanner import PortScannerPlugin
from modules.web.web_scanner import WebVulnScannerPlugin
from modules.system.system_scanner import SystemVulnScannerPlugin
from reports.report_generator import ReportManager
from config.settings import get_config, load_config_file
from config.logging_config import setup_logging, get_logger


class VulnScannerCLI:
    """Интерфейс командной строки для сканера уязвимостей."""
    
    def __init__(self):
        self.scanner = None
        self.report_manager = None
        self.logger = None
        self.current_session_id = None
        
        # Настройка обработчиков сигналов для корректного завершения
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Обработка сигналов прерывания для корректного завершения."""
        print("\nПолучен сигнал прерывания. Корректное завершение работы...")
        if self.scanner and self.current_session_id:
            self.scanner.cancel_session(self.current_session_id)
        if self.scanner:
            self.scanner.shutdown()
        sys.exit(0)
    
    def _setup_argument_parser(self) -> argparse.ArgumentParser:
        """Настройка парсера аргументов командной строки."""
        parser = argparse.ArgumentParser(
            description="Расширенный сканер уязвимостей",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""Примеры:
  %(prog)s -t 192.168.1.1 -p 80,443 --modules network,web
  %(prog)s -t example.com --config custom_config.yaml -o report.json
  %(prog)s -t localhost --modules system --format html,json
  %(prog)s --targets targets.txt --modules all --output-dir /tmp/reports
"""
        )
        
        # Указание цели
        target_group = parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument(
            '-t', '--target',
            help='Одна цель для сканирования (IP-адрес или имя хоста)'
        )
        target_group.add_argument(
            '--targets',
            help='Файл с списком целей (по одной в строке)'
        )
        
        # Указание портов
        parser.add_argument(
            '-p', '--ports',
            help='Порты для сканирования (например, 80,443,8080 или 1-1000)',
            default='1-1000'
        )
        
        # Выбор модулей
        parser.add_argument(
            '--modules',
            help='Модули сканирования для использования (network,web,system или all)',
            default='all'
        )
        
        # Конфигурация
        parser.add_argument(
            '--config',
            help='Путь к файлу конфигурации (YAML или JSON)',
            default=None
        )
        
        # Параметры вывода
        parser.add_argument(
            '-o', '--output',
            help='Имя выходного файла (расширение определяет формат)'
        )
        parser.add_argument(
            '--format',
            help='Формат(ы) отчёта: json,html,text (через запятую)',
            default='json'
        )
        parser.add_argument(
            '--output-dir',
            help='Каталог для сохранения отчётов',
            default='reports'
        )
        
        # Параметры сканирования
        parser.add_argument(
            '--threads',
            type=int,
            help='Максимальное количество потоков для использования',
            default=10
        )
        parser.add_argument(
            '--timeout',
            type=int,
            help='Тайм-аут для отдельных сканов (секунды)',
            default=30
        )
        parser.add_argument(
            '--delay',
            type=float,
            help='Задержка между запросами (секунды)',
            default=0.1
        )
        
        # Детализация вывода
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Включить подробный вывод'
        )
        parser.add_argument(
            '--debug',
            action='store_true',
            help='Включить отладочный вывод'
        )
        
        # Прочие опции
        parser.add_argument(
            '--no-color',
            action='store_true',
            help='Отключить цветной вывод'
        )
        parser.add_argument(
            '--version',
            action='version',
            version='RNTechScan 1.0.0'
        )
        
        return parser
    
    def _parse_targets(self, args) -> List[ScanTarget]:
        """Парсинг указания целей из аргументов командной строки."""
        targets = []
        
        if args.target:
            # Одна цель
            target = ScanTarget(
                host=args.target,
                ports=self._parse_ports(args.ports)
            )
            targets.append(target)
        
        elif args.targets:
            # Несколько целей из файла
            try:
                with open(args.targets, 'r') as f:
                    for line in f:
                        host = line.strip()
                        if host and not host.startswith('#'):
                            target = ScanTarget(
                                host=host,
                                ports=self._parse_ports(args.ports)
                            )
                            targets.append(target)
            except FileNotFoundError:
                print(f"Ошибка: Файл с целями не найден: {args.targets}")
                sys.exit(1)
            except Exception as e:
                print(f"Ошибка чтения файла с целями: {e}")
                sys.exit(1)
        
        return targets
    
    def _parse_ports(self, port_string: str) -> List[int]:
        """Парсинг строки с указанием портов в список портов."""
        ports = []
        
        for part in port_string.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
    
    def _setup_scanner(self, args) -> None:
        """Настройка движка сканера с конфигурацией."""
        # Загрузить конфигурацию
        config = get_config()
        if args.config:
            load_config_file(args.config)
            config = get_config()
        
        # Переопределить конфигурацию аргументами командной строки
        if args.threads:
            config.set('scanner.max_threads', args.threads)
        if args.timeout:
            config.set('scanner.timeout', args.timeout)
        if args.delay:
            config.set('scanner.delay_between_requests', args.delay)
        if args.output_dir:
            config.set('reporting.output_dir', args.output_dir)
        
        # Настроить логирование
        log_level = 'DEBUG' if args.debug else 'INFO' if args.verbose else 'WARNING'
        self.logger = setup_logging(log_level=log_level)
        
        # Создать движок сканера
        self.scanner = ScanEngine(config.to_dict())
        
        # Настроить обратные вызовы прогресса
        self.scanner.on_vulnerability_found = self._on_vulnerability_found
        self.scanner.on_scan_progress = self._on_scan_progress
        self.scanner.on_plugin_completed = self._on_plugin_completed
        
        # Зарегистрировать плагины на основе выбора модулей
        self._register_plugins(args.modules, config.to_dict())
        
        # Настроить менеджер отчётов
        self.report_manager = ReportManager(config.to_dict())
    
    def _register_plugins(self, modules_str: str, config: Dict[str, Any]) -> None:
        """Регистрация плагинов сканирования на основе выбора модулей."""
        modules = [m.strip().lower() for m in modules_str.split(',')]
        
        if self.scanner is None:
            return
        
        if 'all' in modules or 'network' in modules:
            network_config = config.get('modules', {}).get('network', {})
            self.scanner.register_plugin(PortScannerPlugin(network_config))
        
        if 'all' in modules or 'web' in modules:
            web_config = config.get('modules', {}).get('web', {})
            self.scanner.register_plugin(WebVulnScannerPlugin(web_config))
        
        if 'all' in modules or 'system' in modules:
            system_config = config.get('modules', {}).get('system', {})
            self.scanner.register_plugin(SystemVulnScannerPlugin(system_config))
    
    def _on_vulnerability_found(self, vulnerability) -> None:
        """Коллбэк при обнаружении уязвимости."""
        severity_colors = {
            'critical': '\033[91m',  # Красный
            'high': '\033[93m',      # Жёлтый
            'medium': '\033[94m',    # Синий
            'low': '\033[92m',       # Зелёный
            'info': '\033[96m'       # Голубой
        }
        reset_color = '\033[0m'
        
        color = severity_colors.get(vulnerability.severity.value, '')
        print(f"{color}[{vulnerability.severity.value.upper()}] {vulnerability.name} on {vulnerability.target}{reset_color}")
    
    def _on_scan_progress(self, session_id: str, current: int, total: int) -> None:
        """Коллбэк для обновлений прогресса сканирования."""
        progress = (current / total) * 100
        print(f"Scan progress: {current}/{total} targets ({progress:.1f}%)")
    
    def _on_plugin_completed(self, plugin_name: str, result) -> None:
        """Коллбэк при завершении работы плагина."""
        print(f"Plugin {plugin_name} completed: {result.vulnerability_count} vulnerabilities found")
    
    def _generate_reports(self, session_id: str, args) -> None:
        """Генерация отчётов для сессии сканирования."""
        if self.scanner is None or self.report_manager is None:
            print("Ошибка: Сканер или менеджер отчётов не инициализирован")
            return
            
        session = self.scanner.get_session_results(session_id)
        if not session:
            print(f"Error: Session {session_id} not found")
            return
        
        # Определить форматы вывода
        formats = [f.strip().lower() for f in args.format.split(',')]
        
        try:
            # Сгенерировать отчёты
            if args.output:
                # Пользователь указал выходной файл
                output_path = Path(args.output)
                format_from_ext = output_path.suffix[1:].lower()  # Убрать точку
                if format_from_ext in ['json', 'html', 'txt']:
                    generator = self.report_manager.generators.get(
                        'text' if format_from_ext == 'txt' else format_from_ext
                    )
                    if generator:
                        report_file = generator.generate_report(session.to_dict(), args.output)
                        print(f"Report generated: {report_file}")
                    else:
                        print(f"Ошибка: Неизвестный формат из расширения файла: {format_from_ext}")
                else:
                    print(f"Ошибка: Неизвестное расширение файла: {output_path.suffix}")
            else:
                # Сгенерировать отчёты в указанных форматах
                report_files = self.report_manager.generate_reports(session.to_dict(), formats)
                for report_file in report_files:
                    print(f"Report generated: {report_file}")
                    
        except Exception as e:
            print(f"Ошибка при генерации отчётов: {e}")
            if self.logger:
                self.logger.error(f"Ошибка генерации отчётов: {e}")
    
    def run(self, args=None) -> int:
        """Запуск CLI сканера уязвимостей."""
        parser = self._setup_argument_parser()
        args = parser.parse_args(args)
        
        try:
            # Разобрать цели
            targets = self._parse_targets(args)
            if not targets:
                print("Ошибка: Не указаны допустимые цели")
                return 1
            
            print(f"Начало сканирования уязвимостей на {len(targets)} целях...")
            
            # Настроить сканер
            self._setup_scanner(args)
            
            # Начать сканирование
            if self.scanner is None:
                print("Ошибка: Сканер не инициализирован")
                return 1
                
            self.current_session_id = self.scanner.scan_multiple_targets(targets)
            
            # Ждать завершения сканирования
            while True:
                status = self.scanner.get_session_status(self.current_session_id)
                if status in ['completed', 'error', 'cancelled']:
                    break
                import time
                time.sleep(1)
            
            # Получить финальные результаты
            session = self.scanner.get_session_results(self.current_session_id)
            if session:
                total_vulns = sum(r.vulnerability_count for r in session.results or [])
                print(f"\nScan completed. Found {total_vulns} total vulnerabilities.")
                
                # Генерировать отчёты
                self._generate_reports(self.current_session_id, args)
            
            return 0
            
        except KeyboardInterrupt:
            print("Прерывание сканирования пользователем\n")
            return 1
        except Exception as e:
            print(f"Ошибка: {e}")
            if self.logger:
                self.logger.error(f"Ошибка сканера: {e}")
            return 1
        finally:
            if self.scanner:
                self.scanner.shutdown()


def main():
    """Основная точка входа для CLI."""
    cli = VulnScannerCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())