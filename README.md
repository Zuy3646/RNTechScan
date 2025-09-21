# RNTechScan - Расширенный сканер уязвимостей

Модульный, расширяемый сканер уязвимостей, написанный на Python с поддержкой сканирования сетевой безопасности, веб-приложений и системной безопасности.

## Возможности

- **Модульная архитектура**: Плагинная система для лёгкого расширения
- **Многопоточное сканирование**: Параллельное выполнение для быстрого сканирования
- **Множественные форматы отчётов**: Вывод в форматах JSON, HTML и текст
- **Настраиваемость**: Поддержка конфигурации YAML/JSON
- **Интерфейс командной строки**: Простой в использовании CLI с широкими возможностями
- **Множественные типы сканирования**:
  - Сканирование сетевых портов
  - Обнаружение уязвимостей веб-приложений
  - Оценка системной безопасности

## Установка

### Требования

- Python 3.8 или выше
- pip (установщик пакетов Python)

### Установка из исходного кода

```bash
# Клонировать или скачать проект
cd RNTechScan

# Установить зависимости
pip install -r requirements.txt

# Опционально: Установить в режиме разработки
pip install -e .
```

### Установить только зависимости

```bash
pip install requests PyYAML
```

## Быстрый старт

### Основное использование

```bash
# Сканировать одну цель
python main.py -t 192.168.1.1

# Сканировать определённые порты
python main.py -t example.com -p 80,443,8080

# Сканировать с определёнными модулями
python main.py -t localhost --modules network,web

# Создать HTML отчёт
python main.py -t 192.168.1.1 --format html

# Использовать пользовательскую конфигурацию
python main.py -t target.com --config config.yaml
```

### Продвинутое использование

```bash
# Сканировать несколько целей из файла
python main.py --targets targets.txt --modules all

# Пользовательский каталог вывода и формат
python main.py -t example.com --output-dir /tmp/scans --format json,html,text

# Подробный вывод с отладкой
python main.py -t 192.168.1.1 -v --debug

# Ограничить потоки и установить тайм-аут
python main.py -t target.com --threads 5 --timeout 60
```

## Конфигурация

### Файл конфигурации

Создайте файл конфигурации на основе примера:

```bash
cp config/config_example.yaml config.yaml
```

Отредактируйте файл конфигурации для настройки поведения сканера:

```yaml
scanner:
  max_threads: 10
  timeout: 30
  delay_between_requests: 0.1

modules:
  network:
    enabled: true
    port_scan_range: "1-1000"
  web:
    enabled: true
    follow_redirects: true
  system:
    enabled: true
    check_services: true

reporting:
  output_dir: "reports"
  format: ["json", "html"]
  include_details: true
```

### Command Line Options

```
usage: main.py [-h] (-t TARGET | --targets TARGETS) [-p PORTS] [--modules MODULES]
               [--config CONFIG] [-o OUTPUT] [--format FORMAT] [--output-dir OUTPUT_DIR]
               [--threads THREADS] [--timeout TIMEOUT] [--delay DELAY] [-v] [--debug]
               [--no-color] [--version]

Advanced Vulnerability Scanner

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single target to scan (IP address or hostname)
  --targets TARGETS     File containing list of targets (one per line)
  -p PORTS, --ports PORTS
                        Ports to scan (e.g., 80,443,8080 or 1-1000)
  --modules MODULES     Scanning modules to use (network,web,system or all)
  --config CONFIG       Configuration file path (YAML or JSON)
  -o OUTPUT, --output OUTPUT
                        Output file name (extension determines format)
  --format FORMAT       Report format(s): json,html,text (comma-separated)
  --output-dir OUTPUT_DIR
                        Output directory for reports
  --threads THREADS     Maximum number of threads to use
  --timeout TIMEOUT     Timeout for individual scans (seconds)
  --delay DELAY         Delay between requests (seconds)
  -v, --verbose         Enable verbose output
  --debug               Enable debug output
  --no-color            Disable colored output
  --version             show program's version number and exit
```

## Modules

### Network Module

Performs network port scanning and service detection:

- TCP/UDP port scanning
- Service identification
- Open port analysis
- Security risk assessment

### Web Module

Scans web applications for common vulnerabilities:

- Cross-Site Scripting (XSS)
- SQL Injection
- Directory Traversal
- Security Headers
- Information Disclosure
- Weak Authentication

### System Module

Analyzes local system security (localhost only):

- File permissions
- Service configuration
- User privileges
- Package updates
- System configuration

## Output Formats

### JSON Report

Structured data format suitable for automation and integration:

```json
{
  "scan_info": {
    "session_id": "scan_1234567890",
    "start_time": "2024-01-01T12:00:00",
    "status": "completed"
  },
  "statistics": {
    "critical": 2,
    "high": 5,
    "medium": 10
  },
  "vulnerabilities": [...]
}
```

### HTML Report

Interactive web-based report with:
- Executive summary
- Vulnerability details
- Severity breakdown
- Expandable sections
- Professional styling

### Text Report

Plain text format for simple viewing and printing.

## Development

### Project Structure

```
RNTechScan/
├── core/                 # Core scanner engine
│   ├── __init__.py
│   ├── plugin_base.py   # Base plugin classes
│   └── scanner.py       # Main scanner engine
├── modules/             # Scanning modules
│   ├── network/         # Network scanning
│   ├── web/            # Web application scanning
│   └── system/         # System scanning
├── reports/            # Report generators
│   ├── __init__.py
│   └── report_generator.py
├── config/             # Configuration
│   ├── __init__.py
│   ├── settings.py
│   ├── logging_config.py
│   └── config_example.yaml
├── tests/              # Unit tests
├── docs/               # Documentation
├── main.py             # Main entry point
├── cli.py              # Command line interface
├── requirements.txt    # Dependencies
├── setup.py           # Setup script
└── README.md          # This file
```

### Adding Custom Plugins

1. Create a new plugin class inheriting from `BasePlugin`
2. Implement required methods:
   - `get_name()`
   - `get_description()`
   - `get_version()`
   - `is_applicable()`
   - `scan()`

3. Register the plugin with the scanner engine

Example plugin:

```python
from core.plugin_base import BasePlugin, ScanResult, Vulnerability, SeverityLevel

class CustomPlugin(BasePlugin):
    def get_name(self) -> str:
        return "CustomPlugin"
    
    def get_description(self) -> str:
        return "Custom vulnerability scanner plugin"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_applicable(self, target: ScanTarget) -> bool:
        return True  # Applicable to all targets
    
    def scan(self, target: ScanTarget) -> ScanResult:
        result = ScanResult(target, self.get_name())
        
        # Perform scanning logic here
        # Add vulnerabilities to result
        
        result.finish("completed")
        return result
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest

# Run with coverage
pytest --cov=.
```

## Security Considerations

**Important**: This tool is designed for authorized security testing only. 

- Only scan systems you own or have explicit permission to test
- Be aware of rate limiting and potential service disruption
- Some scans may trigger security alerts
- Follow responsible disclosure practices for any vulnerabilities found
- Consider legal and ethical implications before scanning

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Run with appropriate privileges for system scans
   - Check file permissions for config and output directories

2. **Network Timeouts**
   - Increase timeout values in configuration
   - Reduce thread count for stability
   - Check network connectivity

3. **Import Errors**
   - Ensure all dependencies are installed
   - Check Python path configuration
   - Verify Python version compatibility

4. **Configuration Errors**
   - Validate YAML/JSON syntax
   - Check file paths and permissions
   - Use example configuration as reference

### Debug Mode

Enable debug mode for detailed logging:

```bash
python main.py -t target.com --debug
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run existing tests
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The developers assume no liability for misuse of this software.

## Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Review existing documentation
- Check configuration examples
- Enable debug mode for troubleshooting