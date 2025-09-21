"""
System vulnerability scanner plugin for local system checks.
"""
import os
import platform
import subprocess
import stat
from typing import List, Dict, Any, Optional
from pathlib import Path

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


class SystemVulnScannerPlugin(BasePlugin):
    """Plugin for scanning local system vulnerabilities."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = get_logger(self.__class__.__name__)
        self.check_services = config.get('check_services', True)
        self.check_files = config.get('check_files', True)
        self.check_permissions = config.get('check_permissions', True)
        self.check_packages = config.get('check_packages', True)
        
        # Sensitive file paths to check
        self.sensitive_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/ssh/sshd_config',
            '/var/log/auth.log',
            '/var/log/secure',
            '/home/*/.ssh/id_rsa',
            '/root/.ssh/id_rsa',
            '/etc/mysql/my.cnf',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf'
        ]
        
        # Dangerous services that shouldn't be running
        self.dangerous_services = [
            'telnet',
            'rsh',
            'rlogin',
            'rexec',
            'finger',
            'netstat'
        ]
    
    def get_name(self) -> str:
        return "SystemVulnScanner"
    
    def get_description(self) -> str:
        return "Scans local system for security vulnerabilities and misconfigurations"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_applicable(self, target: ScanTarget) -> bool:
        """System scanning is applicable to localhost targets."""
        return target.host in ['localhost', '127.0.0.1', '::1'] or target.host == platform.node()
    
    def get_supported_services(self) -> List[str]:
        return ['System', 'Local']
    
    def scan(self, target: ScanTarget) -> ScanResult:
        """Perform system vulnerability scan."""
        result = ScanResult(target, self.get_name())
        
        try:
            self.logger.info(f"Starting system vulnerability scan on {target.host}")
            
            if self.check_services:
                self._check_running_services(result)
            
            if self.check_files:
                self._check_file_permissions(result)
                self._check_sensitive_files(result)
            
            if self.check_permissions:
                self._check_user_permissions(result)
                self._check_sudo_configuration(result)
            
            if self.check_packages:
                self._check_outdated_packages(result)
            
            # System-specific checks
            self._check_system_configuration(result)
            self._check_network_configuration(result)
            
            self.logger.info(f"System vulnerability scan completed on {target.host}")
            
        except Exception as e:
            self.logger.error(f"System vulnerability scan failed on {target.host}: {e}")
            result.finish("error", str(e))
            return result
        
        result.finish("completed")
        return result
    
    def _run_command(self, command: List[str]) -> Optional[str]:
        """Run a system command and return output."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout if result.returncode == 0 else None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return None
    
    def _check_running_services(self, result: ScanResult) -> None:
        """Check for dangerous or unnecessary running services."""
        try:
            # Check systemd services on Linux
            if platform.system() == "Linux":
                services_output = self._run_command(['systemctl', 'list-units', '--type=service', '--state=running'])
                if services_output:
                    for service in self.dangerous_services:
                        if service in services_output:
                            vulnerability = Vulnerability(
                                id=f"dangerous_service_{service}",
                                name=f"Dangerous Service Running: {service}",
                                description=f"The {service} service is running and may pose security risks",
                                severity=SeverityLevel.HIGH,
                                confidence=0.9,
                                target="localhost",
                                service=service,
                                evidence=f"Service {service} found in running services list",
                                solution=f"Disable the {service} service if not needed: systemctl disable {service}",
                                references=[
                                    "https://linux.die.net/man/8/systemctl",
                                    "https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units"
                                ]
                            )
                            result.add_vulnerability(vulnerability)
            
            # Check for services listening on all interfaces
            netstat_output = self._run_command(['netstat', '-tuln'])
            if netstat_output:
                for line in netstat_output.split('\n'):
                    if '0.0.0.0:' in line and any(port in line for port in ['21', '23', '135', '139', '445']):
                        port = line.split(':')[1].split()[0]
                        vulnerability = Vulnerability(
                            id=f"service_all_interfaces_{port}",
                            name=f"Service Listening on All Interfaces: Port {port}",
                            description=f"A service on port {port} is listening on all network interfaces (0.0.0.0)",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.8,
                            target="localhost",
                            port=int(port),
                            evidence=f"netstat shows service listening on 0.0.0.0:{port}",
                            solution=f"Configure the service to listen only on necessary interfaces",
                            references=["https://linux.die.net/man/8/netstat"]
                        )
                        result.add_vulnerability(vulnerability)
                        
        except Exception as e:
            self.logger.debug(f"Error checking services: {e}")
    
    def _check_file_permissions(self, result: ScanResult) -> None:
        """Check for improper file permissions."""
        try:
            # Check for world-writable files
            if platform.system() == "Linux":
                world_writable = self._run_command(['find', '/', '-type', 'f', '-perm', '-002', '!', '-path', '/proc/*', '!', '-path', '/sys/*'])
                if world_writable:
                    files = world_writable.strip().split('\n')[:10]  # Limit to first 10
                    for file_path in files:
                        if file_path.strip():
                            vulnerability = Vulnerability(
                                id=f"world_writable_file_{hash(file_path)}",
                                name=f"World-Writable File: {file_path}",
                                description=f"File {file_path} is writable by all users",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.9,
                                target="localhost",
                                evidence=f"File permissions allow world write access: {file_path}",
                                solution=f"Remove world write permissions: chmod o-w {file_path}",
                                references=["https://linux.die.net/man/1/chmod"]
                            )
                            result.add_vulnerability(vulnerability)
            
            # Check for SUID/SGID files
            if platform.system() == "Linux":
                suid_files = self._run_command(['find', '/', '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '!', '-path', '/proc/*'])
                if suid_files:
                    files = suid_files.strip().split('\n')
                    suspicious_suid = []
                    for file_path in files:
                        if file_path.strip() and any(name in file_path.lower() for name in ['nmap', 'tcpdump', 'wireshark', 'nc', 'netcat']):
                            suspicious_suid.append(file_path.strip())
                    
                    for file_path in suspicious_suid:
                        vulnerability = Vulnerability(
                            id=f"suspicious_suid_{hash(file_path)}",
                            name=f"Suspicious SUID/SGID Binary: {file_path}",
                            description=f"Potentially dangerous binary {file_path} has SUID/SGID permissions",
                            severity=SeverityLevel.HIGH,
                            confidence=0.8,
                            target="localhost",
                            evidence=f"SUID/SGID binary found: {file_path}",
                            solution=f"Review if SUID/SGID permissions are necessary: chmod u-s,g-s {file_path}",
                            references=["https://en.wikipedia.org/wiki/Setuid"]
                        )
                        result.add_vulnerability(vulnerability)
                        
        except Exception as e:
            self.logger.debug(f"Error checking file permissions: {e}")
    
    def _check_sensitive_files(self, result: ScanResult) -> None:
        """Check access permissions on sensitive files."""
        for file_pattern in self.sensitive_files:
            try:
                # Handle glob patterns
                if '*' in file_pattern:
                    import glob
                    files = glob.glob(file_pattern)
                else:
                    files = [file_pattern] if os.path.exists(file_pattern) else []
                
                for file_path in files:
                    if os.path.exists(file_path):
                        file_stat = os.stat(file_path)
                        mode = file_stat.st_mode
                        
                        # Check if file is readable by others
                        if mode & stat.S_IROTH:
                            severity = SeverityLevel.HIGH if 'shadow' in file_path or 'id_rsa' in file_path else SeverityLevel.MEDIUM
                            
                            vulnerability = Vulnerability(
                                id=f"sensitive_file_readable_{hash(file_path)}",
                                name=f"Sensitive File Readable by Others: {file_path}",
                                description=f"Sensitive file {file_path} is readable by other users",
                                severity=severity,
                                confidence=0.9,
                                target="localhost",
                                evidence=f"File permissions: {oct(mode)[-3:]}",
                                solution=f"Restrict file permissions: chmod o-r {file_path}",
                                references=["https://linux.die.net/man/1/chmod"]
                            )
                            result.add_vulnerability(vulnerability)
                            
            except Exception as e:
                self.logger.debug(f"Error checking sensitive file {file_pattern}: {e}")
    
    def _check_user_permissions(self, result: ScanResult) -> None:
        """Check for user permission issues."""
        try:
            # Check for users with UID 0 (root privileges)
            if platform.system() == "Linux":
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                            vulnerability = Vulnerability(
                                id=f"uid_zero_user_{parts[0]}",
                                name=f"Non-root User with UID 0: {parts[0]}",
                                description=f"User {parts[0]} has UID 0 (root privileges)",
                                severity=SeverityLevel.CRITICAL,
                                confidence=0.95,
                                target="localhost",
                                evidence=f"User {parts[0]} found in /etc/passwd with UID 0",
                                solution=f"Change the UID of user {parts[0]} or remove the account if unnecessary",
                                references=["https://linux.die.net/man/5/passwd"]
                            )
                            result.add_vulnerability(vulnerability)
            
            # Check for empty password fields
            if platform.system() == "Linux" and os.path.exists('/etc/shadow'):
                try:
                    with open('/etc/shadow', 'r') as f:
                        for line in f:
                            parts = line.strip().split(':')
                            if len(parts) >= 2 and (parts[1] == '' or parts[1] == '*' or parts[1] == '!'):
                                continue  # These are disabled accounts
                            elif len(parts) >= 2 and len(parts[1]) < 13:  # Very short hash indicates weak/empty password
                                vulnerability = Vulnerability(
                                    id=f"weak_password_{parts[0]}",
                                    name=f"Weak Password Hash: {parts[0]}",
                                    description=f"User {parts[0]} may have a weak or empty password",
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.7,
                                    target="localhost",
                                    evidence=f"Short password hash found for user {parts[0]}",
                                    solution=f"Ensure user {parts[0]} has a strong password",
                                    references=["https://linux.die.net/man/5/shadow"]
                                )
                                result.add_vulnerability(vulnerability)
                except PermissionError:
                    pass  # Expected if not running as root
                    
        except Exception as e:
            self.logger.debug(f"Error checking user permissions: {e}")
    
    def _check_sudo_configuration(self, result: ScanResult) -> None:
        """Check sudo configuration for security issues."""
        try:
            if platform.system() == "Linux" and os.path.exists('/etc/sudoers'):
                # Check for NOPASSWD entries
                sudo_output = self._run_command(['sudo', '-l'])
                if sudo_output and 'NOPASSWD' in sudo_output:
                    vulnerability = Vulnerability(
                        id="sudo_nopasswd",
                        name="Sudo NOPASSWD Configuration",
                        description="Sudo is configured to allow commands without password verification",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.8,
                        target="localhost",
                        evidence="NOPASSWD found in sudo configuration",
                        solution="Review sudo configuration and remove NOPASSWD where not necessary",
                        references=["https://linux.die.net/man/5/sudoers"]
                    )
                    result.add_vulnerability(vulnerability)
                    
        except Exception as e:
            self.logger.debug(f"Error checking sudo configuration: {e}")
    
    def _check_outdated_packages(self, result: ScanResult) -> None:
        """Check for outdated packages that may have security vulnerabilities."""
        try:
            if platform.system() == "Linux":
                # Ubuntu/Debian
                apt_output = self._run_command(['apt', 'list', '--upgradable'])
                if apt_output and len(apt_output.split('\n')) > 5:  # More than just headers
                    vulnerability = Vulnerability(
                        id="outdated_packages_apt",
                        name="Outdated Packages Available",
                        description="There are outdated packages that may contain security vulnerabilities",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.7,
                        target="localhost",
                        evidence=f"apt list --upgradable shows {len(apt_output.split())} packages",
                        solution="Update packages regularly: apt update && apt upgrade",
                        references=["https://ubuntu.com/security"]
                    )
                    result.add_vulnerability(vulnerability)
                
                # CentOS/RHEL
                yum_output = self._run_command(['yum', 'check-update'])
                if yum_output and 'updates' in yum_output.lower():
                    vulnerability = Vulnerability(
                        id="outdated_packages_yum",
                        name="Outdated Packages Available (YUM)",
                        description="There are outdated packages that may contain security vulnerabilities",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.7,
                        target="localhost",
                        evidence="yum check-update shows available updates",
                        solution="Update packages regularly: yum update",
                        references=["https://access.redhat.com/security/"]
                    )
                    result.add_vulnerability(vulnerability)
                    
        except Exception as e:
            self.logger.debug(f"Error checking packages: {e}")
    
    def _check_system_configuration(self, result: ScanResult) -> None:
        """Check system configuration for security issues."""
        try:
            # Check kernel version
            kernel_version = platform.release()
            if kernel_version:
                # This is a simplified check - in practice, you'd compare against known vulnerable versions
                vulnerability = Vulnerability(
                    id=f"kernel_version_info",
                    name=f"Kernel Version Information",
                    description=f"System is running kernel version {kernel_version}",
                    severity=SeverityLevel.INFO,
                    confidence=0.9,
                    target="localhost",
                    evidence=f"Kernel version: {kernel_version}",
                    solution="Regularly update the kernel to the latest stable version",
                    references=["https://www.kernel.org/"]
                )
                result.add_vulnerability(vulnerability)
            
            # Check for core dumps enabled
            if platform.system() == "Linux":
                ulimit_output = self._run_command(['ulimit', '-c'])
                if ulimit_output and ulimit_output.strip() != '0':
                    vulnerability = Vulnerability(
                        id="core_dumps_enabled",
                        name="Core Dumps Enabled",
                        description="Core dumps are enabled, which may leak sensitive information",
                        severity=SeverityLevel.LOW,
                        confidence=0.8,
                        target="localhost",
                        evidence=f"ulimit -c shows: {ulimit_output.strip()}",
                        solution="Disable core dumps: ulimit -c 0",
                        references=["https://linux.die.net/man/1/ulimit"]
                    )
                    result.add_vulnerability(vulnerability)
                    
        except Exception as e:
            self.logger.debug(f"Error checking system configuration: {e}")
    
    def _check_network_configuration(self, result: ScanResult) -> None:
        """Check network configuration for security issues."""
        try:
            if platform.system() == "Linux":
                # Check if IP forwarding is enabled
                if os.path.exists('/proc/sys/net/ipv4/ip_forward'):
                    with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                        ip_forward = f.read().strip()
                        if ip_forward == '1':
                            vulnerability = Vulnerability(
                                id="ip_forwarding_enabled",
                                name="IP Forwarding Enabled",
                                description="IP forwarding is enabled, which may pose security risks",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.9,
                                target="localhost",
                                evidence="IP forwarding is set to 1 in /proc/sys/net/ipv4/ip_forward",
                                solution="Disable IP forwarding if not needed: echo 0 > /proc/sys/net/ipv4/ip_forward",
                                references=["https://linux.die.net/man/7/ip"]
                            )
                            result.add_vulnerability(vulnerability)
                
                # Check for promiscuous mode network interfaces
                ip_output = self._run_command(['ip', 'link', 'show'])
                if ip_output and 'PROMISC' in ip_output:
                    vulnerability = Vulnerability(
                        id="promiscuous_mode_interface",
                        name="Network Interface in Promiscuous Mode",
                        description="A network interface is running in promiscuous mode",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.8,
                        target="localhost",
                        evidence="PROMISC flag found in network interface configuration",
                        solution="Investigate why the interface is in promiscuous mode and disable if unnecessary",
                        references=["https://linux.die.net/man/8/ip"]
                    )
                    result.add_vulnerability(vulnerability)
                    
        except Exception as e:
            self.logger.debug(f"Error checking network configuration: {e}")