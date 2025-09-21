"""
Task management and scan history system.
"""
import sqlite3
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from .plugin_base import ScanResult
from config.logging_config import get_logger
from config.settings import get_config


class TaskStatus(Enum):
    """Task status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanTask:
    """Represents a scan task."""
    task_id: str
    name: str
    description: str
    targets: List[str]
    modules: List[str]
    config: Dict[str, Any]
    status: TaskStatus
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    session_id: Optional[str] = None
    report_paths: Optional[List[str]] = None
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.report_paths is None:
            self.report_paths = []


@dataclass
class ScanHistory:
    """Represents scan history entry."""
    history_id: str
    task_id: str
    session_id: str
    targets: List[str]
    vulnerabilities_found: int
    scan_duration: float
    timestamp: float
    report_path: Optional[str] = None


class TaskManager:
    """Manages scan tasks and history."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.logger = get_logger(self.__class__.__name__)
        self.config = get_config()
        
        # Database configuration
        self.db_path = db_path or self.config.get('task_manager.db_path', 'scanner_tasks.db')
        self.db_path = Path(self.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize the task management database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tasks table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS tasks (
                        task_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        targets TEXT NOT NULL,
                        modules TEXT NOT NULL,
                        config TEXT,
                        status TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        started_at REAL,
                        completed_at REAL,
                        session_id TEXT,
                        report_paths TEXT,
                        error_message TEXT
                    )
                ''')
                
                # Scan history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_history (
                        history_id TEXT PRIMARY KEY,
                        task_id TEXT NOT NULL,
                        session_id TEXT NOT NULL,
                        targets TEXT NOT NULL,
                        vulnerabilities_found INTEGER NOT NULL,
                        scan_duration REAL NOT NULL,
                        timestamp REAL NOT NULL,
                        report_path TEXT,
                        FOREIGN KEY (task_id) REFERENCES tasks (task_id)
                    )
                ''')
                
                # Scheduled tasks table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scheduled_tasks (
                        schedule_id TEXT PRIMARY KEY,
                        task_id TEXT NOT NULL,
                        schedule_type TEXT NOT NULL,
                        schedule_config TEXT NOT NULL,
                        next_run REAL NOT NULL,
                        enabled BOOLEAN DEFAULT 1,
                        created_at REAL NOT NULL,
                        FOREIGN KEY (task_id) REFERENCES tasks (task_id)
                    )
                ''')
                
                # Audit log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_log (
                        log_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        action TEXT NOT NULL,
                        details TEXT,
                        user_id TEXT,
                        ip_address TEXT
                    )
                ''')
                
                # Create indices
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks (status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks (created_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_history_timestamp ON scan_history (timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_schedule_next_run ON scheduled_tasks (next_run)')
                
                conn.commit()
                self.logger.info("Task management database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize task database: {e}")
            raise
    
    def create_task(self, name: str, description: str, targets: List[str], 
                   modules: List[str], config: Dict[str, Any]) -> str:
        """Create a new scan task."""
        import uuid
        
        task_id = str(uuid.uuid4())
        
        task = ScanTask(
            task_id=task_id,
            name=name,
            description=description,
            targets=targets,
            modules=modules,
            config=config,
            status=TaskStatus.PENDING,
            created_at=time.time()
        )
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO tasks (
                        task_id, name, description, targets, modules, config,
                        status, created_at, started_at, completed_at,
                        session_id, report_paths, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    task.task_id, task.name, task.description,
                    json.dumps(task.targets), json.dumps(task.modules),
                    json.dumps(task.config), task.status.value,
                    task.created_at, task.started_at, task.completed_at,
                    task.session_id, json.dumps(task.report_paths),
                    task.error_message
                ))
                
                conn.commit()
                
            self.logger.info(f"Created task {task_id}: {name}")
            self._log_audit_action("create_task", {"task_id": task_id, "name": name})
            
            return task_id
            
        except Exception as e:
            self.logger.error(f"Failed to create task: {e}")
            raise
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        """Get a task by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM tasks WHERE task_id = ?', (task_id,))
                row = cursor.fetchone()
                
                if row:
                    return ScanTask(
                        task_id=row[0],
                        name=row[1],
                        description=row[2],
                        targets=json.loads(row[3]),
                        modules=json.loads(row[4]),
                        config=json.loads(row[5]) if row[5] else {},
                        status=TaskStatus(row[6]),
                        created_at=row[7],
                        started_at=row[8],
                        completed_at=row[9],
                        session_id=row[10],
                        report_paths=json.loads(row[11]) if row[11] else [],
                        error_message=row[12]
                    )
                
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get task {task_id}: {e}")
            return None
    
    def update_task_status(self, task_id: str, status: TaskStatus, 
                          session_id: Optional[str] = None,
                          error_message: Optional[str] = None,
                          report_paths: Optional[List[str]] = None) -> bool:
        """Update task status."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                current_time = time.time()
                
                # Prepare update values
                updates = ["status = ?"]
                values: List[Any] = [status.value]
                
                if status == TaskStatus.RUNNING:
                    updates.append("started_at = ?")
                    values.append(current_time)
                elif status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                    updates.append("completed_at = ?")
                    values.append(current_time)
                
                if session_id:
                    updates.append("session_id = ?")
                    values.append(session_id)
                
                if error_message:
                    updates.append("error_message = ?")
                    values.append(error_message)
                
                if report_paths:
                    updates.append("report_paths = ?")
                    values.append(json.dumps(report_paths))
                
                values.append(task_id)
                
                cursor.execute(
                    f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = ?",
                    values
                )
                
                success = cursor.rowcount > 0
                conn.commit()
                
                if success:
                    self.logger.info(f"Updated task {task_id} status to {status.value}")
                    self._log_audit_action("update_task_status", {
                        "task_id": task_id, 
                        "status": status.value,
                        "session_id": session_id
                    })
                
                return success
                
        except Exception as e:
            self.logger.error(f"Failed to update task {task_id}: {e}")
            return False
    
    def list_tasks(self, status: Optional[TaskStatus] = None, 
                  limit: int = 100, offset: int = 0) -> List[ScanTask]:
        """List tasks with optional filtering."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if status:
                    cursor.execute('''
                        SELECT * FROM tasks 
                        WHERE status = ? 
                        ORDER BY created_at DESC 
                        LIMIT ? OFFSET ?
                    ''', (status.value, limit, offset))
                else:
                    cursor.execute('''
                        SELECT * FROM tasks 
                        ORDER BY created_at DESC 
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))
                
                tasks = []
                for row in cursor.fetchall():
                    task = ScanTask(
                        task_id=row[0],
                        name=row[1],
                        description=row[2],
                        targets=json.loads(row[3]),
                        modules=json.loads(row[4]),
                        config=json.loads(row[5]) if row[5] else {},
                        status=TaskStatus(row[6]),
                        created_at=row[7],
                        started_at=row[8],
                        completed_at=row[9],
                        session_id=row[10],
                        report_paths=json.loads(row[11]) if row[11] else [],
                        error_message=row[12]
                    )
                    tasks.append(task)
                
                return tasks
                
        except Exception as e:
            self.logger.error(f"Failed to list tasks: {e}")
            return []
    
    def add_scan_history(self, task_id: str, session_id: str, targets: List[str],
                        vulnerabilities_found: int, scan_duration: float,
                        report_path: Optional[str] = None) -> str:
        """Add scan history entry."""
        import uuid
        
        history_id = str(uuid.uuid4())
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO scan_history (
                        history_id, task_id, session_id, targets,
                        vulnerabilities_found, scan_duration, timestamp, report_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    history_id, task_id, session_id, json.dumps(targets),
                    vulnerabilities_found, scan_duration, time.time(), report_path
                ))
                
                conn.commit()
                
            self.logger.info(f"Added scan history {history_id} for task {task_id}")
            return history_id
            
        except Exception as e:
            self.logger.error(f"Failed to add scan history: {e}")
            raise
    
    def get_scan_history(self, task_id: Optional[str] = None, 
                        limit: int = 100, offset: int = 0) -> List[ScanHistory]:
        """Get scan history with optional filtering."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if task_id:
                    cursor.execute('''
                        SELECT * FROM scan_history 
                        WHERE task_id = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ? OFFSET ?
                    ''', (task_id, limit, offset))
                else:
                    cursor.execute('''
                        SELECT * FROM scan_history 
                        ORDER BY timestamp DESC 
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))
                
                history = []
                for row in cursor.fetchall():
                    entry = ScanHistory(
                        history_id=row[0],
                        task_id=row[1],
                        session_id=row[2],
                        targets=json.loads(row[3]),
                        vulnerabilities_found=row[4],
                        scan_duration=row[5],
                        timestamp=row[6],
                        report_path=row[7]
                    )
                    history.append(entry)
                
                return history
                
        except Exception as e:
            self.logger.error(f"Failed to get scan history: {e}")
            return []
    
    def get_task_statistics(self) -> Dict[str, Any]:
        """Get task management statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Task counts by status
                cursor.execute('SELECT status, COUNT(*) FROM tasks GROUP BY status')
                task_counts = dict(cursor.fetchall())
                
                # Total vulnerabilities found
                cursor.execute('SELECT SUM(vulnerabilities_found) FROM scan_history')
                total_vulns = cursor.fetchone()[0] or 0
                
                # Recent activity (last 30 days)
                thirty_days_ago = time.time() - (30 * 24 * 3600)
                cursor.execute('''
                    SELECT COUNT(*) FROM scan_history 
                    WHERE timestamp > ?
                ''', (thirty_days_ago,))
                recent_scans = cursor.fetchone()[0] or 0
                
                # Average scan duration
                cursor.execute('SELECT AVG(scan_duration) FROM scan_history')
                avg_duration = cursor.fetchone()[0] or 0
                
                return {
                    "task_counts": task_counts,
                    "total_vulnerabilities": total_vulns,
                    "recent_scans_30d": recent_scans,
                    "average_scan_duration": avg_duration,
                    "database_path": str(self.db_path)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get task statistics: {e}")
            return {}
    
    def cleanup_old_data(self, days: int = 90) -> None:
        """Clean up old task and history data."""
        try:
            cutoff_time = time.time() - (days * 24 * 3600)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clean old completed tasks
                cursor.execute('''
                    DELETE FROM tasks 
                    WHERE status IN (?, ?, ?) AND completed_at < ?
                ''', (TaskStatus.COMPLETED.value, TaskStatus.FAILED.value, 
                      TaskStatus.CANCELLED.value, cutoff_time))
                
                deleted_tasks = cursor.rowcount
                
                # Clean old scan history
                cursor.execute('DELETE FROM scan_history WHERE timestamp < ?', (cutoff_time,))
                deleted_history = cursor.rowcount
                
                conn.commit()
                
                self.logger.info(f"Cleaned up {deleted_tasks} old tasks and {deleted_history} history entries")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
    
    def _log_audit_action(self, action: str, details: Dict[str, Any],
                         user_id: Optional[str] = None, ip_address: Optional[str] = None) -> None:
        """Log audit action."""
        try:
            import uuid
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO audit_log (log_id, timestamp, action, details, user_id, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()), time.time(), action, json.dumps(details),
                    user_id, ip_address
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.debug(f"Failed to log audit action: {e}")
    
    def get_audit_log(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get audit log entries."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM audit_log 
                    ORDER BY timestamp DESC 
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
                
                logs = []
                for row in cursor.fetchall():
                    log_entry = {
                        "log_id": row[0],
                        "timestamp": row[1],
                        "action": row[2],
                        "details": json.loads(row[3]) if row[3] else {},
                        "user_id": row[4],
                        "ip_address": row[5]
                    }
                    logs.append(log_entry)
                
                return logs
                
        except Exception as e:
            self.logger.error(f"Failed to get audit log: {e}")
            return []


# Global task manager instance
task_manager = None

def get_task_manager() -> TaskManager:
    """Get the global task manager instance."""
    global task_manager
    if task_manager is None:
        task_manager = TaskManager()
    return task_manager