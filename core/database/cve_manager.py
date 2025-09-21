"""
CVE Database Manager for vulnerability detection and matching.
"""
import sqlite3
import json
import requests
import time
import gzip
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import threading
import re

try:
    from config.logging_config import get_logger
    from config.settings import get_config
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    from config.logging_config import get_logger
    from config.settings import get_config


class CVEDatabase:
    """Менеджер базы данных CVE для обнаружения уязвимостей."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.logger = get_logger(self.__class__.__name__)
        self.config = get_config()
        
        # Конфигурация базы данных
        self.db_path = db_path or self.config.get('cve_database.path', 'cve_database.db')
        self.db_path = Path(self.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # CVE feed URLs
        self.nvd_base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
        self.recent_url = f"{self.nvd_base_url}/nvdcve-1.1-recent.json.gz"
        self.modified_url = f"{self.nvd_base_url}/nvdcve-1.1-modified.json.gz"
        
        # Настройки обновления
        self.auto_update = self.config.get('cve_database.auto_update', True)
        self.update_interval = self.config.get('cve_database.update_interval_hours', 24)
        self.last_update_file = self.db_path.parent / "last_update.txt"
        
        # Инициализировать базу данных
        self._init_database()
        
        # Запустить автообновление, если включено
        if self.auto_update:
            self._start_auto_update()
    
    def _init_database(self) -> None:
        """Инициализация схемы базы данных CVE."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Таблица записей CVE
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cves (
                        id TEXT PRIMARY KEY,
                        description TEXT,
                        published_date TEXT,
                        modified_date TEXT,
                        cvss_score REAL,
                        cvss_vector TEXT,
                        severity TEXT,
                        attack_vector TEXT,
                        attack_complexity TEXT,
                        privileges_required TEXT,
                        user_interaction TEXT,
                        scope TEXT,
                        confidentiality_impact TEXT,
                        integrity_impact TEXT,
                        availability_impact TEXT,
                        cpe_configurations TEXT,
                        references TEXT,
                        raw_data TEXT
                    )
                ''')
                
                # Таблица соответствий CPE (Common Platform Enumeration)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cpe_matches (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cve_id TEXT,
                        cpe_uri TEXT,
                        vendor TEXT,
                        product TEXT,
                        version TEXT,
                        version_start TEXT,
                        version_end TEXT,
                        vulnerable BOOLEAN,
                        FOREIGN KEY (cve_id) REFERENCES cves (id)
                    )
                ''')
                
                # Таблица отпечатков сервисов
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS service_fingerprints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service_name TEXT,
                        version_pattern TEXT,
                        banner_pattern TEXT,
                        port INTEGER,
                        protocol TEXT,
                        vendor TEXT,
                        product TEXT,
                        version TEXT
                    )
                ''')
                
                # Таблица истории сканирования
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT,
                        target TEXT,
                        timestamp TEXT,
                        vulnerabilities_found INTEGER,
                        scan_duration REAL,
                        scan_status TEXT,
                        report_path TEXT
                    )
                ''')
                
                # Таблица метаданных обновления
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS update_metadata (
                        feed_name TEXT PRIMARY KEY,
                        last_update TEXT,
                        last_modified TEXT,
                        record_count INTEGER
                    )
                ''')
                
                # Создать индексы для лучшей производительности
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves (severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_score ON cves (cvss_score)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_matches (product)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_cpe_vendor ON cpe_matches (vendor)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_service_product ON service_fingerprints (product)')
                
                conn.commit()
                self.logger.info("CVE database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize CVE database: {e}")
            raise
    
    def update_database(self, force: bool = False) -> bool:
        """Обновление базы данных CVE из каналов NVD."""
        try:
            if not force and not self._should_update():
                self.logger.info("CVE database is up to date")
                return True
            
            self.logger.info("Starting CVE database update...")
            
            # Скачать и обработать последние CVE
            recent_count = self._download_and_process_feed(self.recent_url, "recent")
            
            # Скачать и обработать изменённые CVE
            modified_count = self._download_and_process_feed(self.modified_url, "modified")
            
            # Обновить отпечатки сервисов
            self._update_service_fingerprints()
            
            # Записать время обновления
            self._record_update_time()
            
            total_count = recent_count + modified_count
            self.logger.info(f"CVE database updated successfully. Processed {total_count} CVEs")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update CVE database: {e}")
            return False
    
    def _should_update(self) -> bool:
        """Проверить, нужно ли обновлять базу данных."""
        if not self.last_update_file.exists():
            return True
        
        try:
            with open(self.last_update_file, 'r') as f:
                last_update_str = f.read().strip()
                last_update = datetime.fromisoformat(last_update_str)
                
            time_diff = datetime.now() - last_update
            return time_diff.total_seconds() > (self.update_interval * 3600)
            
        except Exception:
            return True
    
    def _download_and_process_feed(self, url: str, feed_name: str) -> int:
        """Скачать и обработать канал CVE."""
        try:
            self.logger.info(f"Downloading {feed_name} CVE feed...")
            
            response = requests.get(url, timeout=300)
            response.raise_for_status()
            
            # Распаковать gzip данные
            decompressed_data = gzip.decompress(response.content)
            cve_data = json.loads(decompressed_data.decode('utf-8'))
            
            count = 0
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for item in cve_data.get('CVE_Items', []):
                    try:
                        self._process_cve_item(cursor, item)
                        count += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to process CVE item: {e}")
                
                # Обновить метаданные
                cursor.execute('''
                    INSERT OR REPLACE INTO update_metadata 
                    (feed_name, last_update, last_modified, record_count)
                    VALUES (?, ?, ?, ?)
                ''', (feed_name, datetime.now().isoformat(), 
                      cve_data.get('CVE_data_timestamp', ''), count))
                
                conn.commit()
            
            self.logger.info(f"Processed {count} CVEs from {feed_name} feed")
            return count
            
        except Exception as e:
            self.logger.error(f"Failed to download/process {feed_name} feed: {e}")
            return 0
    
    def _process_cve_item(self, cursor: sqlite3.Cursor, item: Dict[str, Any]) -> None:
        """Обработать один элемент CVE и вставить в базу данных."""
        cve = item.get('cve', {})
        impact = item.get('impact', {})
        configurations = item.get('configurations', {})
        
        # Extract basic CVE information
        cve_id = cve.get('CVE_data_meta', {}).get('ID', '')
        
        # Description
        descriptions = cve.get('description', {}).get('description_data', [])
        description = descriptions[0].get('value', '') if descriptions else ''
        
        # Dates
        published_date = item.get('publishedDate', '')
        modified_date = item.get('lastModifiedDate', '')
        
        # CVSS scores
        cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
        cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})
        
        cvss_score = cvss_v3.get('baseScore', cvss_v2.get('baseScore', 0.0))
        cvss_vector = cvss_v3.get('vectorString', cvss_v2.get('vectorString', ''))
        severity = cvss_v3.get('baseSeverity', cvss_v2.get('baseSeverity', 'UNKNOWN')).upper()
        
        # CVSS metrics
        attack_vector = cvss_v3.get('attackVector', '')
        attack_complexity = cvss_v3.get('attackComplexity', '')
        privileges_required = cvss_v3.get('privilegesRequired', '')
        user_interaction = cvss_v3.get('userInteraction', '')
        scope = cvss_v3.get('scope', '')
        confidentiality_impact = cvss_v3.get('confidentialityImpact', '')
        integrity_impact = cvss_v3.get('integrityImpact', '')
        availability_impact = cvss_v3.get('availabilityImpact', '')
        
        # References
        references = json.dumps([ref.get('url', '') for ref in cve.get('references', {}).get('reference_data', [])])
        
        # CPE configurations
        cpe_configurations = json.dumps(configurations)
        
        # Raw data for future processing
        raw_data = json.dumps(item)
        
        # Insert CVE data
        cursor.execute('''
            INSERT OR REPLACE INTO cves (
                id, description, published_date, modified_date, cvss_score, cvss_vector,
                severity, attack_vector, attack_complexity, privileges_required,
                user_interaction, scope, confidentiality_impact, integrity_impact,
                availability_impact, cpe_configurations, references, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, description, published_date, modified_date, cvss_score, cvss_vector,
              severity, attack_vector, attack_complexity, privileges_required,
              user_interaction, scope, confidentiality_impact, integrity_impact,
              availability_impact, cpe_configurations, references, raw_data))
        
        # Process CPE matches
        self._process_cpe_matches(cursor, cve_id, configurations)
    
    def _process_cpe_matches(self, cursor: sqlite3.Cursor, cve_id: str, configurations: Dict[str, Any]) -> None:
        """Обработать соответствия CPE для CVE."""
        # Clear existing matches for this CVE
        cursor.execute('DELETE FROM cpe_matches WHERE cve_id = ?', (cve_id,))
        
        nodes = configurations.get('nodes', [])
        for node in nodes:
            cpe_matches = node.get('cpe_match', [])
            for match in cpe_matches:
                cpe_uri = match.get('cpe23Uri', '')
                vulnerable = match.get('vulnerable', False)
                version_start = match.get('versionStartIncluding', match.get('versionStartExcluding', ''))
                version_end = match.get('versionEndIncluding', match.get('versionEndExcluding', ''))
                
                # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
                cpe_parts = cpe_uri.split(':')
                vendor = cpe_parts[3] if len(cpe_parts) > 3 else ''
                product = cpe_parts[4] if len(cpe_parts) > 4 else ''
                version = cpe_parts[5] if len(cpe_parts) > 5 else ''
                
                cursor.execute('''
                    INSERT INTO cpe_matches (
                        cve_id, cpe_uri, vendor, product, version,
                        version_start, version_end, vulnerable
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (cve_id, cpe_uri, vendor, product, version,
                      version_start, version_end, vulnerable))
    
    def _update_service_fingerprints(self) -> None:
        """Обновить базу данных отпечатков сервисов."""
        fingerprints = [
            # Web servers
            ('apache', r'Apache[/\\s]+([\\d\\.]+)', r'Server:\\s*Apache[/\\s]+([\\d\\.]+)', 80, 'tcp', 'apache', 'http_server'),
            ('nginx', r'nginx[/\\s]+([\\d\\.]+)', r'Server:\\s*nginx[/\\s]+([\\d\\.]+)', 80, 'tcp', 'nginx', 'http_server'),
            ('iis', r'Microsoft-IIS[/\\s]+([\\d\\.]+)', r'Server:\\s*Microsoft-IIS[/\\s]+([\\d\\.]+)', 80, 'tcp', 'microsoft', 'iis'),
            
            # Databases
            ('mysql', r'MySQL[\\s]+([\\d\\.]+)', r'([\\d\\.]+)-MySQL', 3306, 'tcp', 'mysql', 'mysql'),
            ('postgresql', r'PostgreSQL[\\s]+([\\d\\.]+)', r'PostgreSQL[\\s]+([\\d\\.]+)', 5432, 'tcp', 'postgresql', 'postgresql'),
            ('mongodb', r'MongoDB[\\s]+([\\d\\.]+)', r'MongoDB[\\s]+([\\d\\.]+)', 27017, 'tcp', 'mongodb', 'mongodb'),
            
            # SSH
            ('openssh', r'OpenSSH[_\\s]+([\\d\\.]+)', r'SSH-[\\d\\.]+-OpenSSH[_\\s]+([\\d\\.]+)', 22, 'tcp', 'openbsd', 'openssh'),
            
            # FTP
            ('vsftpd', r'vsftpd[\\s]+([\\d\\.]+)', r'\\(vsFTPd[\\s]+([\\d\\.]+)\\)', 21, 'tcp', 'beasts', 'vsftpd'),
            ('proftpd', r'ProFTPD[\\s]+([\\d\\.]+)', r'ProFTPD[\\s]+([\\d\\.]+)', 21, 'tcp', 'proftpd', 'proftpd'),
        ]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clear existing fingerprints
                cursor.execute('DELETE FROM service_fingerprints')
                
                for service_name, version_pattern, banner_pattern, port, protocol, vendor, product in fingerprints:
                    cursor.execute('''
                        INSERT INTO service_fingerprints (
                            service_name, version_pattern, banner_pattern,
                            port, protocol, vendor, product, version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (service_name, version_pattern, banner_pattern,
                          port, protocol, vendor, product, ''))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to update service fingerprints: {e}")
    
    def _record_update_time(self) -> None:
        """Записать время последнего обновления."""
        try:
            with open(self.last_update_file, 'w') as f:
                f.write(datetime.now().isoformat())
        except Exception as e:
            self.logger.warning(f"Failed to record update time: {e}")
    
    def _start_auto_update(self) -> None:
        """Запустить автоматические обновления базы данных в фоновом режиме."""
        def update_worker():
            while True:
                try:
                    time.sleep(self.update_interval * 3600)  # Convert hours to seconds
                    if self._should_update():
                        self.update_database()
                except Exception as e:
                    self.logger.error(f"Auto-update failed: {e}")
        
        update_thread = threading.Thread(target=update_worker, daemon=True)
        update_thread.start()
        self.logger.info("Auto-update thread started")
    
    def search_vulnerabilities_by_service(self, vendor: str, product: str, version: str) -> List[Dict[str, Any]]:
        """Поиск уязвимостей, затрагивающих конкретный сервис."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Search for exact matches first
                cursor.execute('''
                    SELECT DISTINCT c.* FROM cves c
                    JOIN cpe_matches cm ON c.id = cm.cve_id
                    WHERE cm.vendor = ? AND cm.product = ? AND cm.vulnerable = 1
                    AND (cm.version = ? OR cm.version = '*' OR cm.version = '')
                    ORDER BY c.cvss_score DESC
                ''', (vendor.lower(), product.lower(), version))
                
                results = []
                for row in cursor.fetchall():
                    cve_dict = {
                        'id': row[0],
                        'description': row[1],
                        'published_date': row[2],
                        'modified_date': row[3],
                        'cvss_score': row[4],
                        'cvss_vector': row[5],
                        'severity': row[6],
                        'attack_vector': row[7],
                        'attack_complexity': row[8],
                        'privileges_required': row[9],
                        'user_interaction': row[10],
                        'scope': row[11],
                        'confidentiality_impact': row[12],
                        'integrity_impact': row[13],
                        'availability_impact': row[14],
                        'references': json.loads(row[16]) if row[16] else []
                    }
                    results.append(cve_dict)
                
                # If no exact matches, try version range matches
                if not results and version:
                    cursor.execute('''
                        SELECT DISTINCT c.* FROM cves c
                        JOIN cpe_matches cm ON c.id = cm.cve_id
                        WHERE cm.vendor = ? AND cm.product = ? AND cm.vulnerable = 1
                        AND (
                            (cm.version_start != '' AND ? >= cm.version_start) OR
                            (cm.version_end != '' AND ? <= cm.version_end)
                        )
                        ORDER BY c.cvss_score DESC
                    ''', (vendor.lower(), product.lower(), version, version))
                    
                    for row in cursor.fetchall():
                        cve_dict = {
                            'id': row[0],
                            'description': row[1],
                            'cvss_score': row[4],
                            'severity': row[6],
                            'references': json.loads(row[16]) if row[16] else []
                        }
                        results.append(cve_dict)
                
                return results
                
        except Exception as e:
            self.logger.error(f"Failed to search vulnerabilities: {e}")
            return []
    
    def identify_service_from_banner(self, banner: str, port: int) -> Optional[Tuple[str, str, str]]:
        """Определить сервис и версию по баннеру."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT vendor, product, version_pattern, banner_pattern 
                    FROM service_fingerprints 
                    WHERE port = ? OR port IS NULL
                ''', (port,))
                
                for row in cursor.fetchall():
                    vendor, product, version_pattern, banner_pattern = row
                    
                    # Try to match banner pattern
                    banner_match = re.search(banner_pattern, banner, re.IGNORECASE)
                    if banner_match:
                        # Extract version if pattern includes capture group
                        version = banner_match.group(1) if banner_match.groups() else ''
                        return vendor, product, version
                
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to identify service from banner: {e}")
            return None
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Получить статистику базы данных."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Count CVEs by severity
                cursor.execute('SELECT severity, COUNT(*) FROM cves GROUP BY severity')
                severity_counts = dict(cursor.fetchall())
                
                # Total CVEs
                cursor.execute('SELECT COUNT(*) FROM cves')
                total_cves = cursor.fetchone()[0]
                
                # Last update info
                cursor.execute('SELECT feed_name, last_update FROM update_metadata')
                update_info = dict(cursor.fetchall())
                
                # Top vendors by vulnerability count
                cursor.execute('''
                    SELECT vendor, COUNT(DISTINCT cve_id) as vuln_count 
                    FROM cpe_matches 
                    WHERE vulnerable = 1 
                    GROUP BY vendor 
                    ORDER BY vuln_count DESC 
                    LIMIT 10
                ''')
                top_vendors = cursor.fetchall()
                
                return {
                    'total_cves': total_cves,
                    'severity_counts': severity_counts,
                    'last_updates': update_info,
                    'top_vulnerable_vendors': top_vendors
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {e}")
            return {}
    
    def cleanup_old_data(self, days: int = 365) -> None:
        """Очистить старые данные CVE."""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete old CVEs
                cursor.execute('DELETE FROM cves WHERE published_date < ?', (cutoff_date,))
                deleted_count = cursor.rowcount
                
                # Delete orphaned CPE matches
                cursor.execute('''
                    DELETE FROM cpe_matches 
                    WHERE cve_id NOT IN (SELECT id FROM cves)
                ''')
                
                conn.commit()
                
                self.logger.info(f"Cleaned up {deleted_count} old CVE records")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
    
    def close(self) -> None:
        """Закрыть соединения с базой данных и очистить."""
        # Database connections are closed automatically with context managers
        self.logger.info("CVE database manager closed")


# Global CVE database instance
cve_db = None

def get_cve_database() -> CVEDatabase:
    """Получить глобальный экземпляр базы данных CVE."""
    global cve_db
    if cve_db is None:
        cve_db = CVEDatabase()
    return cve_db