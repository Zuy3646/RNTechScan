"""
Плагин сканирования сетевых портов для обнаружения уязвимостей.
"""
import socket
import threading
import time
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

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


class PortScannerPlugin(BasePlugin):
    """Плагин для сканирования сетевых портов и обнаружения открытых сервисов."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = get_logger(self.__class__.__name__)
        self.scan_timeout = config.get('scan_timeout', 3)
        self.max_threads = config.get('max_threads', 50)
        self.scan_type = config.get('scan_type', 'tcp')  # tcp, udp, both
        self.port_range = self._parse_port_range(config.get('port_scan_range', '1-1000'))
        
        # Общие уязвимые сервисы и их типичные порты
        self.vulnerable_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            27017: 'MongoDB'
        }
    
    def get_name(self) -> str:
        return "PortScanner"
    
    def get_description(self) -> str:
        return "Scans network ports to identify open services and potential entry points"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_applicable(self, target: ScanTarget) -> bool:
        """Port scanning is applicable to all targets."""
        return True
    
    def get_supported_services(self) -> List[str]:
        return list(self.vulnerable_services.values())
    
    def _parse_port_range(self, port_range_str: str) -> List[int]:
        """Parse port range string into list of ports."""
        ports = []
        
        for part in port_range_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
    
    def scan(self, target: ScanTarget) -> ScanResult:
        """Perform port scan on the target."""
        result = ScanResult(target, self.get_name())
        
        try:
            self.logger.info(f"Starting port scan on {target.host}")
            
            # Use target's specific ports if provided, otherwise use configured range
            ports_to_scan = target.ports if target.ports else self.port_range
            
            open_ports = []
            
            if self.scan_type in ['tcp', 'both']:
                tcp_ports = self._scan_tcp_ports(target.host, ports_to_scan)
                open_ports.extend([(port, 'tcp') for port in tcp_ports])
            
            if self.scan_type in ['udp', 'both']:
                udp_ports = self._scan_udp_ports(target.host, ports_to_scan)
                open_ports.extend([(port, 'udp') for port in udp_ports])
            
            # Analyze results and create vulnerabilities
            for port, protocol in open_ports:
                vulnerability = self._analyze_open_port(target.host, port, protocol)
                if vulnerability:
                    result.add_vulnerability(vulnerability)
            
            result.metadata['open_ports'] = open_ports
            result.metadata['total_ports_scanned'] = len(ports_to_scan)
            
            self.logger.info(
                f"Port scan completed on {target.host}. "
                f"Found {len(open_ports)} open ports out of {len(ports_to_scan)} scanned."
            )
            
        except Exception as e:
            self.logger.error(f"Port scan failed on {target.host}: {e}")
            result.finish("error", str(e))
            return result
        
        result.finish("completed")
        return result
    
    def _scan_tcp_ports(self, host: str, ports: List[int]) -> List[int]:
        """Scan TCP ports on the target host."""
        open_ports = []
        
        def scan_port(port: int) -> Optional[int]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    return port
            except Exception:
                pass
            return None
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    def _scan_udp_ports(self, host: str, ports: List[int]) -> List[int]:
        """Scan UDP ports on the target host (simplified version)."""
        open_ports = []
        
        def scan_udp_port(port: int) -> Optional[int]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.scan_timeout)
                
                # Send a simple UDP packet
                sock.sendto(b'\\x00', (host, port))
                
                # Try to receive a response
                try:
                    sock.recvfrom(1024)
                    return port  # Got a response, port is likely open
                except socket.timeout:
                    # No response might mean the port is open but service doesn't respond
                    # or port is filtered/closed
                    pass
                
                sock.close()
            except Exception:
                pass
            return None
        
        # UDP scanning is less reliable and slower, use fewer threads
        max_udp_threads = min(10, len(ports))
        with ThreadPoolExecutor(max_workers=max_udp_threads) as executor:
            future_to_port = {executor.submit(scan_udp_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    def _analyze_open_port(self, host: str, port: int, protocol: str) -> Optional[Vulnerability]:
        """Analyze an open port and create vulnerability if needed."""
        service_name = self.vulnerable_services.get(port, f"Unknown service on port {port}")
        
        # Determine severity based on service type
        severity = self._get_service_severity(port, service_name)
        
        # Get service information
        try:
            service_info = self._get_service_info(host, port, protocol)
        except Exception:
            service_info = "Unable to determine service details"
        
        vulnerability = Vulnerability(
            id=f"open_port_{protocol}_{port}",
            name=f"Open {protocol.upper()} Port: {port}",
            description=f"Port {port}/{protocol} is open and running {service_name}",
            severity=severity,
            confidence=0.9,
            target=host,
            port=port,
            service=service_name,
            evidence=f"TCP connection successful to {host}:{port}. Service: {service_info}",
            solution=self._get_port_solution(port, service_name),
            references=self._get_service_references(port, service_name)
        )
        
        return vulnerability
    
    def _get_service_severity(self, port: int, service_name: str) -> SeverityLevel:
        """Determine severity level based on service type."""
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3389, 5900]  # FTP, Telnet, RPC, NetBIOS, SMB, MSSQL, RDP, VNC
        medium_risk_ports = [22, 80, 443, 3306, 5432, 6379, 27017]  # SSH, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB
        
        if port in high_risk_ports:
            return SeverityLevel.HIGH
        elif port in medium_risk_ports:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _get_service_info(self, host: str, port: int, protocol: str) -> str:
        """Try to get service banner or version information."""
        if protocol != 'tcp':
            return "Service detection not available for UDP"
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Try to receive a banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return f"Banner: {banner[:100]}"
            except:
                pass
            
            # Try sending HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\\r\\nHost: " + host.encode() + b"\\r\\n\\r\\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'HTTP' in response:
                    return f"HTTP service detected: {response[:100]}"
            
            sock.close()
            return "Service responsive but no banner received"
            
        except Exception as e:
            return f"Service detection failed: {str(e)[:50]}"
    
    def _get_port_solution(self, port: int, service_name: str) -> str:
        """Get recommended solution for open port."""
        solutions = {
            21: "Consider using SFTP instead of FTP. If FTP is required, ensure it's properly configured with strong authentication.",
            23: "Telnet is insecure. Replace with SSH for remote access.",
            135: "Disable RPC if not needed. Ensure proper firewall rules are in place.",
            139: "Consider disabling NetBIOS if not required. Ensure proper network segmentation.",
            445: "Ensure SMB is properly secured with strong authentication. Consider SMB signing.",
            1433: "Secure MSSQL with strong authentication, encryption, and network restrictions.",
            3389: "Secure RDP with strong passwords, network level authentication, and consider VPN access.",
            5900: "Secure VNC with strong passwords and consider using it through a VPN."
        }
        
        return solutions.get(port, f"Review if {service_name} on port {port} is necessary and ensure it's properly secured.")
    
    def _get_service_references(self, port: int, service_name: str) -> List[str]:
        """Get security references for the service."""
        return [
            f"https://www.speedguide.net/port.php?port={port}",
            "https://owasp.org/www-community/vulnerabilities/",
            "https://cve.mitre.org/"
        ]