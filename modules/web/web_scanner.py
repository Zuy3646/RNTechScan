"""
Плагин сканера уязвимостей веб-приложений.
"""
import requests
import re
import urllib.parse
from typing import List, Dict, Any, Optional, Set
from requests.adapters import HTTPAdapter

try:
    from core.plugin_base import (
        BasePlugin, ScanTarget, ScanResult, Vulnerability, SeverityLevel
    )
    from config.logging_config import get_logger
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    from core.plugin_base import (
        BasePlugin, ScanTarget, ScanResult, Vulnerability, SeverityLevel
    )
    from config.logging_config import get_logger


class WebVulnScannerPlugin(BasePlugin):
    """Плагин для сканирования веб-приложений на наличие распространённых уязвимостей."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = get_logger(self.__class__.__name__)
        self.follow_redirects = config.get('follow_redirects', True)
        self.verify_ssl = config.get('verify_ssl', False)
        self.max_page_depth = config.get('max_page_depth', 3)
        self.user_agent = config.get('user_agent', 'VulnScanner/1.0')
        
        # Setup requests session with basic retry
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=3)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Общие шаблоны уязвимостей веб-приложений
        self.xss_payloads = [
            "<script>alert('xss')</script>",
            "'\"><script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL--"
        ]
        
        self.directory_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        ]
    
    def get_name(self) -> str:
        return "WebVulnScanner"
    
    def get_description(self) -> str:
        return "Scans web applications for common vulnerabilities like XSS, SQL injection, and information disclosure"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_applicable(self, target: ScanTarget) -> bool:
        """Web scanning is applicable to targets with web services."""
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        return any(port in web_ports for port in target.ports) if target.ports else True
    
    def get_supported_services(self) -> List[str]:
        return ['HTTP', 'HTTPS']
    
    def scan(self, target: ScanTarget) -> ScanResult:
        """Perform web vulnerability scan on the target."""
        result = ScanResult(target, self.get_name())
        
        try:
            self.logger.info(f"Starting web vulnerability scan on {target.host}")
            
            # Determine URLs to scan
            urls_to_scan = self._get_target_urls(target)
            
            for url in urls_to_scan:
                self.logger.debug(f"Scanning URL: {url}")
                
                # Basic information gathering
                self._scan_basic_info(url, result)
                
                # Check for common vulnerabilities
                self._check_xss_vulnerabilities(url, result)
                self._check_sql_injection(url, result)
                self._check_directory_traversal(url, result)
                self._check_security_headers(url, result)
                self._check_information_disclosure(url, result)
                self._check_weak_authentication(url, result)
            
            self.logger.info(f"Web vulnerability scan completed on {target.host}")
            
        except Exception as e:
            self.logger.error(f"Web vulnerability scan failed on {target.host}: {e}")
            result.finish("error", str(e))
            return result
        
        result.finish("completed")
        return result
    
    def _get_target_urls(self, target: ScanTarget) -> List[str]:
        """Generate list of URLs to scan based on target."""
        urls = []
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        
        if target.ports:
            for port in target.ports:
                if port in web_ports:
                    protocol = "https" if port in [443, 8443] else "http"
                    url = f"{protocol}://{target.host}:{port}"
                    urls.append(url)
        else:
            # Default web URLs
            urls.extend([
                f"http://{target.host}",
                f"https://{target.host}"
            ])
        
        return urls
    
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with proper error handling."""
        try:
            headers = kwargs.get('headers', {})
            headers['User-Agent'] = self.user_agent
            kwargs['headers'] = headers
            kwargs['verify'] = self.verify_ssl
            kwargs['timeout'] = self.timeout
            kwargs['allow_redirects'] = self.follow_redirects
            
            response = self.session.request(method, url, **kwargs)
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request failed for {url}: {e}")
            return None
    
    def _scan_basic_info(self, url: str, result: ScanResult) -> None:
        """Gather basic information about the web application."""
        response = self._make_request(url)
        if not response:
            return
        
        # Check for server information
        server_header = response.headers.get('Server', 'Unknown')
        if server_header != 'Unknown':
            vulnerability = Vulnerability(
                id=f"server_disclosure_{hash(url)}",
                name="Server Information Disclosure",
                description=f"Server header reveals technology information: {server_header}",
                severity=SeverityLevel.INFO,
                confidence=0.9,
                target=url,
                evidence=f"Server: {server_header}",
                solution="Configure the web server to not reveal version information in headers.",
                references=["https://owasp.org/www-community/Security_Headers"]
            )
            result.add_vulnerability(vulnerability)
        
        # Check for technology disclosure in headers
        tech_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Generator']
        for header in tech_headers:
            if header in response.headers:
                vulnerability = Vulnerability(
                    id=f"tech_disclosure_{header}_{hash(url)}",
                    name="Technology Information Disclosure",
                    description=f"Header {header} reveals technology information",
                    severity=SeverityLevel.INFO,
                    confidence=0.8,
                    target=url,
                    evidence=f"{header}: {response.headers[header]}",
                    solution=f"Remove or obfuscate the {header} header.",
                    references=["https://owasp.org/www-community/Security_Headers"]
                )
                result.add_vulnerability(vulnerability)
    
    def _check_xss_vulnerabilities(self, url: str, result: ScanResult) -> None:
        """Check for Cross-Site Scripting (XSS) vulnerabilities."""
        # First, try to find forms or parameters
        response = self._make_request(url)
        if not response:
            return
        
        # Look for forms
        forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
        
        for payload in self.xss_payloads:
            # Test URL parameters
            test_url = f"{url}?test={urllib.parse.quote(payload)}"
            test_response = self._make_request(test_url)
            
            if test_response and payload in test_response.text:
                vulnerability = Vulnerability(
                    id=f"xss_reflected_{hash(test_url)}",
                    name="Reflected Cross-Site Scripting (XSS)",
                    description="The application reflects user input without proper sanitization",
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    target=test_url,
                    evidence=f"Payload '{payload}' was reflected in the response",
                    solution="Implement proper input validation and output encoding. Use Content Security Policy (CSP).",
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ]
                )
                result.add_vulnerability(vulnerability)
                break  # Found XSS, no need to test more payloads for this URL
    
    def _check_sql_injection(self, url: str, result: ScanResult) -> None:
        """Check for SQL injection vulnerabilities."""
        for payload in self.sql_injection_payloads:
            # Test URL parameters
            test_url = f"{url}?id={urllib.parse.quote(payload)}"
            test_response = self._make_request(test_url)
            
            if test_response:
                # Look for SQL error patterns
                sql_errors = [
                    r"SQL syntax.*MySQL",
                    r"Warning.*mysql_.*",
                    r"valid MySQL result",
                    r"MySqlClient\.",
                    r"PostgreSQL.*ERROR",
                    r"Warning.*pg_.*",
                    r"valid PostgreSQL result",
                    r"Npgsql\.",
                    r"Microsoft OLE DB Provider for ODBC Drivers",
                    r"Microsoft OLE DB Provider for SQL Server",
                    r"Unclosed quotation mark after the character string",
                    r"'80040e14'",
                    r"mssql_query\(\)",
                    r"Microsoft OLE DB Provider for Oracle",
                    r"wrong number or types of arguments in call to",
                    r"ORA-[0-9][0-9][0-9][0-9]",
                    r"Oracle error",
                    r"Oracle.*Driver",
                    r"Warning.*oci_.*",
                    r"Warning.*ora_.*"
                ]
                
                for error_pattern in sql_errors:
                    if re.search(error_pattern, test_response.text, re.IGNORECASE):
                        vulnerability = Vulnerability(
                            id=f"sql_injection_{hash(test_url)}",
                            name="SQL Injection",
                            description="The application is vulnerable to SQL injection attacks",
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.9,
                            target=test_url,
                            evidence=f"SQL error detected with payload: {payload}",
                            solution="Use parameterized queries or prepared statements. Implement proper input validation.",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                            ]
                        )
                        result.add_vulnerability(vulnerability)
                        return  # Found SQL injection, no need to continue
    
    def _check_directory_traversal(self, url: str, result: ScanResult) -> None:
        """Check for directory traversal vulnerabilities."""
        for payload in self.directory_traversal_payloads:
            test_url = f"{url}?file={urllib.parse.quote(payload)}"
            test_response = self._make_request(test_url)
            
            if test_response:
                # Look for common file content patterns
                file_patterns = [
                    r"root:.*:/bin/bash",  # /etc/passwd
                    r"\[drivers\]",  # Windows hosts file
                    r"# This is a sample HOSTS file"
                ]
                
                for pattern in file_patterns:
                    if re.search(pattern, test_response.text, re.IGNORECASE):
                        vulnerability = Vulnerability(
                            id=f"directory_traversal_{hash(test_url)}",
                            name="Directory Traversal",
                            description="The application is vulnerable to directory traversal attacks",
                            severity=SeverityLevel.HIGH,
                            confidence=0.85,
                            target=test_url,
                            evidence=f"File content detected with payload: {payload}",
                            solution="Implement proper input validation and use whitelisting for file access.",
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
                            ]
                        )
                        result.add_vulnerability(vulnerability)
                        return
    
    def _check_security_headers(self, url: str, result: ScanResult) -> None:
        """Check for missing security headers."""
        response = self._make_request(url)
        if not response:
            return
        
        security_headers = {
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'Enables XSS filtering',
            'Strict-Transport-Security': 'Enforces HTTPS connections',
            'Content-Security-Policy': 'Prevents various injection attacks',
            'Referrer-Policy': 'Controls referrer information'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                vulnerability = Vulnerability(
                    id=f"missing_header_{header}_{hash(url)}",
                    name=f"Missing Security Header: {header}",
                    description=f"The {header} security header is missing. {description}.",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.9,
                    target=url,
                    evidence=f"Response headers do not include {header}",
                    solution=f"Add the {header} security header to all responses.",
                    references=["https://owasp.org/www-community/Security_Headers"]
                )
                result.add_vulnerability(vulnerability)
    
    def _check_information_disclosure(self, url: str, result: ScanResult) -> None:
        """Check for information disclosure vulnerabilities."""
        # Check for common sensitive files
        sensitive_files = [
            "robots.txt",
            ".htaccess",
            "web.config",
            "phpinfo.php",
            "test.php",
            "info.php",
            ".git/config",
            ".svn/entries",
            "backup.sql",
            "config.php.bak"
        ]
        
        for filename in sensitive_files:
            file_url = urllib.parse.urljoin(url, filename)
            response = self._make_request(file_url)
            
            if response and response.status_code == 200:
                vulnerability = Vulnerability(
                    id=f"sensitive_file_{filename}_{hash(url)}",
                    name=f"Sensitive File Accessible: {filename}",
                    description=f"The sensitive file {filename} is accessible",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    target=file_url,
                    evidence=f"HTTP 200 response for {file_url}",
                    solution=f"Remove or restrict access to {filename}.",
                    references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"]
                )
                result.add_vulnerability(vulnerability)
    
    def _check_weak_authentication(self, url: str, result: ScanResult) -> None:
        """Check for weak authentication mechanisms."""
        # Check for default login pages
        login_paths = [
            "/admin",
            "/login",
            "/admin/login",
            "/administrator",
            "/wp-admin",
            "/admin.php",
            "/manager/html"
        ]
        
        for path in login_paths:
            login_url = urllib.parse.urljoin(url, path)
            response = self._make_request(login_url)
            
            if response and response.status_code == 200:
                # Check for default credentials
                if self._test_default_credentials(login_url):
                    vulnerability = Vulnerability(
                        id=f"default_credentials_{hash(login_url)}",
                        name="Default Credentials",
                        description="The application uses default or weak credentials",
                        severity=SeverityLevel.CRITICAL,
                        confidence=0.9,
                        target=login_url,
                        evidence="Default credentials were accepted",
                        solution="Change default credentials to strong, unique passwords.",
                        references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"]
                    )
                    result.add_vulnerability(vulnerability)
    
    def _test_default_credentials(self, login_url: str) -> bool:
        """Test common default credentials."""
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", ""),
            ("root", "root"),
            ("test", "test"),
            ("guest", "guest")
        ]
        
        for username, password in default_creds:
            # This is a simplified test - in practice, you'd need to analyze the login form
            # and submit proper POST data
            data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password,
                'login': username
            }
            
            response = self._make_request(login_url, method="POST", data=data)
            if response and ("welcome" in response.text.lower() or 
                           "dashboard" in response.text.lower() or
                           "logout" in response.text.lower()):
                return True
        
        return False