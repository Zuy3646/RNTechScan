"""
Enhanced vulnerability detection plugin with CVE integration.
"""
import re
import json
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.plugin_base import (
    BasePlugin, ScanTarget, ScanResult, Vulnerability, SeverityLevel
)
from core.database.cve_manager import get_cve_database
from config.logging_config import get_logger


class CVEVulnerabilityDetector(BasePlugin):
    """Plugin for detecting known vulnerabilities using CVE database."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = get_logger(self.__class__.__name__)
        self.cve_db = get_cve_database()
        self.max_cve_results = config.get('max_cve_results', 50)
        self.min_cvss_score = config.get('min_cvss_score', 4.0)
        
        # Service detection patterns
        self.service_patterns = {
            'apache': [
                r'Apache[/\s]+(\d+\.\d+\.?\d*)',
                r'Server:\s*Apache[/\s]+(\d+\.\d+\.?\d*)'
            ],
            'nginx': [
                r'nginx[/\s]+(\d+\.\d+\.?\d*)',
                r'Server:\s*nginx[/\s]+(\d+\.\d+\.?\d*)'
            ],
            'mysql': [
                r'(\d+\.\d+\.?\d*)-MySQL',
                r'MySQL\s+(\d+\.\d+\.?\d*)'
            ],
            'openssh': [
                r'OpenSSH[_\s]+(\d+\.\d+\.?\d*)',
                r'SSH-[\d\.]+-OpenSSH[_\s]+(\d+\.\d+\.?\d*)'
            ],
            'microsoft-iis': [
                r'Microsoft-IIS[/\s]+(\d+\.\d+\.?\d*)',
                r'Server:\s*Microsoft-IIS[/\s]+(\d+\.\d+\.?\d*)'
            ]
        }
    
    def get_name(self) -> str:
        return "CVEVulnerabilityDetector"
    
    def get_description(self) -> str:
        return "Detects known vulnerabilities by matching services against CVE database"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_applicable(self, target: ScanTarget) -> bool:
        """CVE detection is applicable to all targets."""
        return True
    
    def get_supported_services(self) -> List[str]:
        return list(self.service_patterns.keys())
    
    def scan(self, target: ScanTarget) -> ScanResult:
        """Perform CVE-based vulnerability detection."""
        result = ScanResult(target, self.get_name())
        
        try:
            self.logger.info(f"Starting CVE vulnerability detection on {target.host}")
            
            # Get service information from target metadata or detect services
            services = self._detect_services(target, result)
            
            # Search for CVEs for each detected service
            total_cves_found = 0
            for service_info in services:
                cves = self._search_service_cves(service_info)
                total_cves_found += len(cves)
                
                # Create vulnerabilities from CVEs
                for cve in cves:
                    vulnerability = self._create_vulnerability_from_cve(target, service_info, cve)
                    if vulnerability:
                        result.add_vulnerability(vulnerability)
            
            result.metadata['services_detected'] = len(services)
            result.metadata['cves_found'] = total_cves_found
            result.metadata['services'] = services
            
            self.logger.info(
                f"CVE detection completed on {target.host}. "
                f"Found {total_cves_found} CVEs for {len(services)} services."
            )
            
        except Exception as e:
            self.logger.error(f"CVE vulnerability detection failed on {target.host}: {e}")
            result.finish("error", str(e))
            return result
        
        result.finish("completed")
        return result
    
    def _detect_services(self, target: ScanTarget, result: ScanResult) -> List[Dict[str, Any]]:
        """Detect services running on the target."""
        services = []
        
        # Check if services are already provided in target metadata
        if target.services:
            for service in target.services:
                services.append({
                    'name': service.lower(),
                    'vendor': 'unknown',
                    'version': 'unknown',
                    'port': None,
                    'banner': ''
                })
        
        # Try to detect services from banners if available in metadata
        if target.metadata and 'banners' in target.metadata:
            for port, banner in target.metadata['banners'].items():
                service_info = self._parse_service_banner(banner, port)
                if service_info:
                    services.append(service_info)
        
        # If no services detected, try some common service detection
        if not services:
            services = self._basic_service_detection(target)
        
        return services
    
    def _parse_service_banner(self, banner: str, port: int) -> Optional[Dict[str, Any]]:
        """Parse service information from banner."""
        # Try CVE database service identification first
        cve_result = self.cve_db.identify_service_from_banner(banner, port)
        if cve_result:
            vendor, product, version = cve_result
            return {
                'name': product,
                'vendor': vendor,
                'version': version or 'unknown',
                'port': port,
                'banner': banner
            }
        
        # Fallback to pattern matching
        for service_name, patterns in self.service_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else 'unknown'
                    
                    # Determine vendor based on service
                    vendor_map = {
                        'apache': 'apache',
                        'nginx': 'nginx',
                        'mysql': 'mysql',
                        'openssh': 'openbsd',
                        'microsoft-iis': 'microsoft'
                    }
                    
                    return {
                        'name': service_name,
                        'vendor': vendor_map.get(service_name, 'unknown'),
                        'version': version,
                        'port': port,
                        'banner': banner
                    }
        
        return None
    
    def _basic_service_detection(self, target: ScanTarget) -> List[Dict[str, Any]]:
        """Basic service detection based on common ports."""
        services = []
        common_services = {
            22: ('openssh', 'openbsd', 'ssh'),
            80: ('apache', 'apache', 'http'),
            443: ('apache', 'apache', 'https'),
            3306: ('mysql', 'mysql', 'mysql'),
            5432: ('postgresql', 'postgresql', 'postgresql'),
            6379: ('redis', 'redis', 'redis'),
            27017: ('mongodb', 'mongodb', 'mongodb')
        }
        
        if target.ports:
            for port in target.ports:
                if port in common_services:
                    service_name, vendor, protocol = common_services[port]
                    services.append({
                        'name': service_name,
                        'vendor': vendor,
                        'version': 'unknown',
                        'port': port,
                        'banner': f'Detected {protocol} service on port {port}'
                    })
        
        return services
    
    def _search_service_cves(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for CVEs affecting a specific service."""
        vendor = service_info.get('vendor', 'unknown')
        product = service_info.get('name', 'unknown')
        version = service_info.get('version', 'unknown')
        
        if vendor == 'unknown' or product == 'unknown':
            return []
        
        try:
            cves = self.cve_db.search_vulnerabilities_by_service(vendor, product, version)
            
            # Filter by minimum CVSS score
            filtered_cves = [
                cve for cve in cves 
                if cve.get('cvss_score', 0) >= self.min_cvss_score
            ]
            
            # Limit results
            return filtered_cves[:self.max_cve_results]
            
        except Exception as e:
            self.logger.error(f"Failed to search CVEs for {vendor}/{product}: {e}")
            return []
    
    def _create_vulnerability_from_cve(self, target: ScanTarget, service_info: Dict[str, Any], 
                                     cve: Dict[str, Any]) -> Optional[Vulnerability]:
        """Create a vulnerability object from CVE data."""
        try:
            cve_id = cve.get('id', 'unknown')
            cvss_score = cve.get('cvss_score', 0.0)
            
            # Map CVSS score to severity
            if cvss_score >= 9.0:
                severity = SeverityLevel.CRITICAL
            elif cvss_score >= 7.0:
                severity = SeverityLevel.HIGH
            elif cvss_score >= 4.0:
                severity = SeverityLevel.MEDIUM
            elif cvss_score >= 0.1:
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.INFO
            
            # Create vulnerability
            vulnerability = Vulnerability(
                id=f"cve_{cve_id}_{service_info.get('name', 'unknown')}",
                name=f"{cve_id}: {service_info.get('name', 'Unknown Service')} Vulnerability",
                description=cve.get('description', 'No description available'),
                severity=severity,
                confidence=0.8,  # CVE matches are generally reliable
                target=target.host,
                port=service_info.get('port'),
                service=f"{service_info.get('vendor', 'unknown')}/{service_info.get('name', 'unknown')} {service_info.get('version', 'unknown')}",
                evidence=self._generate_evidence(service_info, cve),
                solution=self._generate_solution(service_info, cve),
                references=cve.get('references', [])
            )
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(f"Failed to create vulnerability from CVE {cve.get('id', 'unknown')}: {e}")
            return None
    
    def _generate_evidence(self, service_info: Dict[str, Any], cve: Dict[str, Any]) -> str:
        """Generate evidence text for the vulnerability."""
        evidence_parts = []
        
        # Service information
        service_name = service_info.get('name', 'unknown')
        vendor = service_info.get('vendor', 'unknown')
        version = service_info.get('version', 'unknown')
        port = service_info.get('port')
        
        evidence_parts.append(f"Detected service: {vendor}/{service_name} version {version}")
        
        if port:
            evidence_parts.append(f"Running on port: {port}")
        
        # CVE information
        cve_id = cve.get('id', 'unknown')
        cvss_score = cve.get('cvss_score', 0.0)
        
        evidence_parts.append(f"CVE ID: {cve_id}")
        evidence_parts.append(f"CVSS Score: {cvss_score}")
        
        # Attack vector information
        attack_vector = cve.get('attack_vector', '')
        if attack_vector:
            evidence_parts.append(f"Attack Vector: {attack_vector}")
        
        # Banner information
        banner = service_info.get('banner', '')
        if banner:
            evidence_parts.append(f"Service Banner: {banner[:100]}...")
        
        return "\n".join(evidence_parts)
    
    def _generate_solution(self, service_info: Dict[str, Any], cve: Dict[str, Any]) -> str:
        """Generate solution recommendations."""
        service_name = service_info.get('name', 'unknown')
        vendor = service_info.get('vendor', 'unknown')
        version = service_info.get('version', 'unknown')
        
        solutions = []
        
        # General update recommendation
        if version != 'unknown':
            solutions.append(f"Update {vendor}/{service_name} from version {version} to the latest secure version.")
        else:
            solutions.append(f"Update {vendor}/{service_name} to the latest secure version.")
        
        # Service-specific recommendations
        service_recommendations = {
            'apache': "Consider using mod_security for additional protection. Review and harden Apache configuration.",
            'nginx': "Review nginx configuration for security best practices. Consider using nginx security modules.",
            'mysql': "Ensure MySQL is properly configured with strong passwords and restricted access.",
            'openssh': "Review SSH configuration, disable unnecessary features, use key-based authentication.",
            'postgresql': "Review PostgreSQL security configuration and access controls.",
            'redis': "Ensure Redis is not exposed to public networks. Use authentication and encryption.",
            'mongodb': "Enable MongoDB authentication and use proper access controls."
        }
        
        if service_name in service_recommendations:
            solutions.append(service_recommendations[service_name])
        
        # CVE-specific information
        cve_id = cve.get('id', 'unknown')
        solutions.append(f"Review detailed information about {cve_id} for specific mitigation steps.")
        solutions.append("Consider implementing network segmentation to limit exposure.")
        solutions.append("Monitor security advisories for this software component.")
        
        return "\n".join(solutions)
    
    def get_cve_database_stats(self) -> Dict[str, Any]:
        """Get CVE database statistics."""
        return self.cve_db.get_database_stats()
    
    def update_cve_database(self, force: bool = False) -> bool:
        """Update the CVE database."""
        return self.cve_db.update_database(force)