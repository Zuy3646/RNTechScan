"""
Основной движок сканера для координации сканирования уязвимостей.
"""
import asyncio
import threading
import time
import multiprocessing
import importlib.util
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Callable, Union
from dataclasses import dataclass
import queue
import uuid
from pathlib import Path

from .plugin_base import (
    BasePlugin, PluginManager, ScanTarget, ScanResult, 
    Vulnerability, SeverityLevel
)
try:
    from config.settings import get_config
    from config.logging_config import get_logger
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from config.settings import get_config
    from config.logging_config import get_logger


@dataclass
class ScanJob:
    """Представляет задачу сканирования для параллельного выполнения."""
    job_id: str
    target: ScanTarget
    plugin: BasePlugin
    priority: int = 1
    created_at: float = 0.0
    
    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()


class ScanSession:
    """Представляет полную сессию сканирования."""
    def __init__(self, session_id: str, targets: List[ScanTarget], start_time: float):
        self.session_id = session_id
        self.targets = targets
        self.start_time = start_time
        self.end_time: Optional[float] = None
        self.status: str = "running"
        self.results: List[ScanResult] = []

    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать сессию в словарь."""
        return {
            "session_id": self.session_id,
            "targets": [t.to_dict() for t in self.targets],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "results": [r.to_dict() for r in self.results],
        }


class ScanEngine:
    """Основной движок сканера уязвимостей с расширенными возможностями параллельной обработки."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().to_dict()
        self.logger = get_logger(self.__class__.__name__)
        self.plugin_manager = PluginManager()
        self.active_sessions: Dict[str, ScanSession] = {}
        
        # Parallel execution settings
        self.max_threads = self.config.get('scanner', {}).get('max_threads', 10)
        self.max_processes = self.config.get('scanner', {}).get('max_processes', 4)
        self.use_multiprocessing = self.config.get('scanner', {}).get('use_multiprocessing', False)
        self.job_queue_size = self.config.get('scanner', {}).get('job_queue_size', 1000)
        
        # Execution control
        self.timeout = self.config.get('scanner', {}).get('timeout', 30)
        self.delay_between_requests = self.config.get('scanner', {}).get('delay_between_requests', 0.1)
        self.rate_limit = self.config.get('scanner', {}).get('rate_limit', 100)  # requests per second
        
        # Job management
        self.job_queue = queue.PriorityQueue(maxsize=self.job_queue_size)
        self.active_jobs: Dict[str, ScanJob] = {}
        self.completed_jobs: Dict[str, ScanResult] = {}
        self.job_executor = None
        self.is_running = False
        
        # Rate limiting
        self.last_request_time = 0
        self.request_count = 0
        self.rate_limit_window = time.time()
        
        # Callbacks
        self.on_vulnerability_found: Optional[Callable[[Vulnerability], None]] = None
        self.on_scan_progress: Optional[Callable[[str, int, int], None]] = None
        self.on_plugin_completed: Optional[Callable[[str, ScanResult], None]] = None
        self.on_job_started: Optional[Callable[[ScanJob], None]] = None
        self.on_job_completed: Optional[Callable[[ScanJob, ScanResult], None]] = None
    
    def start_job_executor(self) -> None:
        """Start the job executor for parallel processing."""
        if self.is_running:
            return
        
        self.is_running = True
        
        if self.use_multiprocessing:
            self.job_executor = ProcessPoolExecutor(max_workers=self.max_processes)
            self.logger.info(f"Started process pool executor with {self.max_processes} processes")
        else:
            self.job_executor = ThreadPoolExecutor(max_workers=self.max_threads)
            self.logger.info(f"Started thread pool executor with {self.max_threads} threads")
    
    def stop_job_executor(self) -> None:
        """Stop the job executor."""
        self.is_running = False
        
        if self.job_executor:
            self.job_executor.shutdown(wait=True)
            self.job_executor = None
            self.logger.info("Job executor stopped")
    
    def submit_scan_job(self, target: ScanTarget, plugin: BasePlugin, priority: int = 1) -> str:
        """Submit a scan job for parallel execution."""
        job_id = str(uuid.uuid4())
        
        job = ScanJob(
            job_id=job_id,
            target=target,
            plugin=plugin,
            priority=priority
        )
        
        try:
            # Priority queue uses (priority, item) tuples
            self.job_queue.put((priority, job), timeout=1)
            self.active_jobs[job_id] = job
            
            if self.on_job_started:
                self.on_job_started(job)
            
            self.logger.debug(f"Submitted job {job_id} for {plugin.get_name()} on {target.host}")
            return job_id
            
        except queue.Full:
            self.logger.error(f"Job queue is full, cannot submit job {job_id}")
            raise RuntimeError("Job queue is full")
    
    def execute_jobs_parallel(self, max_concurrent: Optional[int] = None) -> None:
        """Выполнить задачи из очереди параллельно."""
        if not self.job_executor:
            self.start_job_executor()
        
        # Обеспечить, что max_concurrent является допустимым целым числом
        max_concurrent_value: int
        if max_concurrent is None or max_concurrent <= 0:
            max_concurrent_value = self.max_threads
        else:
            max_concurrent_value = max_concurrent
        
        futures = {}
        
        try:
            while self.is_running or not self.job_queue.empty():
                # Submit new jobs up to the limit
                while len(futures) < max_concurrent_value and not self.job_queue.empty():
                    try:
                        priority, job = self.job_queue.get_nowait()
                        
                        # Apply rate limiting
                        self._apply_rate_limit()
                        
                        # Submit job for execution
                        if self.job_executor is not None:
                            future = self.job_executor.submit(self._execute_job_worker, job)
                            futures[future] = job
                            
                            self.logger.debug(f"Started execution of job {job.job_id}")
                        
                    except queue.Empty:
                        break
                
                if not futures:
                    break
                
                # Process completed jobs
                completed_futures = []
                for future in futures:
                    if future.done():
                        completed_futures.append(future)
                
                for future in completed_futures:
                    job = futures.pop(future)
                    
                    try:
                        result = future.result()
                        self.completed_jobs[job.job_id] = result
                        
                        # Remove from active jobs
                        if job.job_id in self.active_jobs:
                            del self.active_jobs[job.job_id]
                        
                        # Call callbacks
                        if self.on_plugin_completed:
                            self.on_plugin_completed(job.plugin.get_name(), result)
                        
                        if self.on_job_completed:
                            self.on_job_completed(job, result)
                        
                        # Process vulnerabilities
                        for vuln in result.vulnerabilities:
                            if self.on_vulnerability_found:
                                self.on_vulnerability_found(vuln)
                        
                        self.logger.debug(f"Completed job {job.job_id}")
                        
                    except Exception as e:
                        self.logger.error(f"Job {job.job_id} failed: {e}")
                        
                        # Create error result
                        error_result = ScanResult(job.target, job.plugin.get_name())
                        error_result.finish("error", str(e))
                        self.completed_jobs[job.job_id] = error_result
                
                # Small delay to prevent busy waiting
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal, stopping job execution")
            self.is_running = False
        
        finally:
            # Wait for remaining futures to complete
            if futures:
                self.logger.info(f"Waiting for {len(futures)} remaining jobs to complete")
                for future in futures:
                    try:
                        future.result(timeout=self.timeout)
                    except Exception as e:
                        self.logger.error(f"Error waiting for job completion: {e}")
    
    def _execute_job_worker(self, job: ScanJob) -> ScanResult:
        """Worker function to execute a single scan job."""
        try:
            self.logger.debug(f"Executing job {job.job_id}: {job.plugin.get_name()} on {job.target.host}")
            
            # Execute the plugin
            result = job.plugin.scan(job.target)
            
            if result.status == "running":
                result.finish("completed")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Job {job.job_id} execution failed: {e}")
            
            # Create error result
            error_result = ScanResult(job.target, job.plugin.get_name())
            error_result.finish("error", str(e))
            return error_result
    
    def _apply_rate_limit(self) -> None:
        """Apply rate limiting to prevent overwhelming targets."""
        current_time = time.time()
        
        # Reset rate limit window if needed
        if current_time - self.rate_limit_window >= 1.0:
            self.rate_limit_window = current_time
            self.request_count = 0
        
        # Check if we've exceeded the rate limit
        if self.request_count >= self.rate_limit:
            sleep_time = 1.0 - (current_time - self.rate_limit_window)
            if sleep_time > 0:
                time.sleep(sleep_time)
                self.rate_limit_window = time.time()
                self.request_count = 0
        
        # Apply delay between requests
        if self.delay_between_requests > 0:
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.delay_between_requests:
                time.sleep(self.delay_between_requests - time_since_last)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def scan_multiple_targets_parallel(self, targets: List[ScanTarget], 
                                      plugins: Optional[List[BasePlugin]] = None,
                                      priority_targets: Optional[List[str]] = None) -> str:
        """Scan multiple targets in parallel with job prioritization."""
        session_id = self.create_scan_session(targets)
        session = self.active_sessions[session_id]
        
        try:
            # Start job executor
            self.start_job_executor()
            
            # Get plugins to use
            if plugins is None:
                all_plugins = list(self.plugin_manager.get_all_plugins().values())
            else:
                all_plugins = plugins
            
            # Submit all jobs
            total_jobs = 0
            priority_hosts = set(priority_targets or [])
            
            for target in targets:
                applicable_plugins = [
                    plugin for plugin in all_plugins 
                    if plugin.enabled and plugin.is_applicable(target)
                ]
                
                for plugin in applicable_plugins:
                    # Higher priority for specified targets
                    priority = 0 if target.host in priority_hosts else 1
                    
                    self.submit_scan_job(target, plugin, priority)
                    total_jobs += 1
            
            self.logger.info(f"Submitted {total_jobs} jobs for {len(targets)} targets")
            
            # Execute jobs in parallel
            self.execute_jobs_parallel()
            
            # Collect results
            all_results = list(self.completed_jobs.values())
            session.results = all_results
            session.end_time = time.time()
            session.status = "completed"
            
            # Clear completed jobs
            self.completed_jobs.clear()
            
            self.logger.info(
                f"Parallel scan session {session_id} completed. "
                f"Found {sum(r.vulnerability_count for r in all_results)} total vulnerabilities."
            )
            
        except Exception as e:
            session.status = "error"
            session.end_time = time.time()
            self.logger.error(f"Parallel scan session {session_id} failed: {e}")
            raise
        
        finally:
            self.stop_job_executor()
        
        return session_id
    
    def register_plugin(self, plugin: BasePlugin) -> None:
        """Register a scanning plugin."""
        try:
            self.plugin_manager.register_plugin(plugin)
            self.logger.info(f"Registered plugin: {plugin.get_name()}")
        except Exception as e:
            self.logger.error(f"Failed to register plugin {plugin.get_name()}: {e}")
    
    def load_plugins_from_directory(self, plugins_dir: str) -> None:
        """Load plugins from a directory."""
        plugins_path = Path(plugins_dir)
        if not plugins_path.exists():
            self.logger.warning(f"Plugins directory not found: {plugins_dir}")
            return
        
        for plugin_file in plugins_path.glob("*.py"):
            if plugin_file.name.startswith("__"):
                continue
                
            try:
                # Import the plugin module
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                if spec is None or spec.loader is None:
                    self.logger.warning(f"Could not load spec for {plugin_file}")
                    continue
                    
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Look for plugin classes
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, BasePlugin) and 
                        attr != BasePlugin):
                        
                        plugin_config = self.config.get('modules', {}).get(module_name, {})
                        plugin_instance = attr(plugin_config)
                        self.register_plugin(plugin_instance)
                        
            except Exception as e:
                self.logger.error(f"Failed to load plugin from {plugin_file}: {e}")
    
    def create_scan_session(self, targets: List[ScanTarget]) -> str:
        """Create a new scan session."""
        session_id = f"scan_{int(time.time())}_{len(self.active_sessions)}"
        session = ScanSession(
            session_id=session_id,
            targets=targets,
            start_time=time.time()
        )
        self.active_sessions[session_id] = session
        self.logger.info(f"Created scan session {session_id} with {len(targets)} targets")
        return session_id
    
    def scan_target(self, target: ScanTarget, plugins: Optional[List[BasePlugin]] = None) -> List[ScanResult]:
        """Scan a single target with specified plugins."""
        if plugins is None:
            plugins = self.plugin_manager.get_applicable_plugins(target)
        
        results = []
        
        self.logger.info(f"Scanning target {target.host} with {len(plugins)} plugins")
        
        # Use thread pool for parallel plugin execution
        with ThreadPoolExecutor(max_workers=min(len(plugins), self.max_threads)) as executor:
            # Submit all plugin tasks
            future_to_plugin = {}
            for plugin in plugins:
                if plugin.enabled:
                    future = executor.submit(self._execute_plugin, plugin, target)
                    future_to_plugin[future] = plugin
            
            # Collect results as they complete
            for future in as_completed(future_to_plugin, timeout=self.timeout * len(plugins)):
                plugin = future_to_plugin[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Call callbacks
                    if self.on_plugin_completed:
                        self.on_plugin_completed(plugin.get_name(), result)
                    
                    # Process found vulnerabilities
                    for vuln in result.vulnerabilities:
                        if self.on_vulnerability_found:
                            self.on_vulnerability_found(vuln)
                    
                    self.logger.info(
                        f"Plugin {plugin.get_name()} found {result.vulnerability_count} "
                        f"vulnerabilities on {target.host}"
                    )
                    
                except Exception as e:
                    self.logger.error(f"Plugin {plugin.get_name()} failed on {target.host}: {e}")
                    # Create error result
                    error_result = ScanResult(target, plugin.get_name())
                    error_result.finish("error", str(e))
                    results.append(error_result)
                
                # Add delay between requests if configured
                if self.delay_between_requests > 0:
                    time.sleep(self.delay_between_requests)
        
        return results
    
    def _execute_plugin(self, plugin: BasePlugin, target: ScanTarget) -> ScanResult:
        """Execute a single plugin against a target."""
        self.logger.debug(f"Executing plugin {plugin.get_name()} on {target.host}")
        
        try:
            result = plugin.scan(target)
            if result.status == "running":
                result.finish("completed")
            return result
        except Exception as e:
            self.logger.error(f"Plugin {plugin.get_name()} execution failed: {e}")
            result = ScanResult(target, plugin.get_name())
            result.finish("error", str(e))
            return result
    
    def scan_multiple_targets(self, targets: List[ScanTarget], 
                            plugins: Optional[List[BasePlugin]] = None) -> str:
        """Scan multiple targets and return session ID."""
        session_id = self.create_scan_session(targets)
        session = self.active_sessions[session_id]
        
        try:
            all_results = []
            total_targets = len(targets)
            
            for i, target in enumerate(targets):
                target_results = self.scan_target(target, plugins)
                all_results.extend(target_results)
                
                # Progress callback
                if self.on_scan_progress:
                    self.on_scan_progress(session_id, i + 1, total_targets)
                
                self.logger.info(f"Completed target {i + 1}/{total_targets}: {target.host}")
            
            session.results = all_results
            session.end_time = time.time()
            session.status = "completed"
            
            self.logger.info(
                f"Scan session {session_id} completed. "
                f"Found {sum(r.vulnerability_count for r in all_results)} total vulnerabilities."
            )
            
        except Exception as e:
            session.status = "error"
            session.end_time = time.time()
            self.logger.error(f"Scan session {session_id} failed: {e}")
            raise
        
        return session_id
    
    def get_session_results(self, session_id: str) -> Optional[ScanSession]:
        """Get results for a scan session."""
        return self.active_sessions.get(session_id)
    
    def get_session_status(self, session_id: str) -> Optional[str]:
        """Get status of a scan session."""
        session = self.active_sessions.get(session_id)
        return session.status if session else None
    
    def cancel_session(self, session_id: str) -> bool:
        """Cancel an active scan session."""
        session = self.active_sessions.get(session_id)
        if session and session.status == "running":
            session.status = "cancelled"
            session.end_time = time.time()
            self.logger.info(f"Cancelled scan session {session_id}")
            return True
        return False
    
    def cleanup_session(self, session_id: str) -> None:
        """Remove a completed scan session from memory."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            self.logger.debug(f"Cleaned up session {session_id}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        sessions_by_status: Dict[str, int] = {}
        total_vulnerabilities = 0
        
        # Count vulnerabilities and session statuses
        for session in self.active_sessions.values():
            status = session.status
            if status not in sessions_by_status:
                sessions_by_status[status] = 0
            sessions_by_status[status] += 1
            
            if session.results:
                total_vulnerabilities += sum(r.vulnerability_count for r in session.results)
        
        stats = {
            "active_sessions": len(self.active_sessions),
            "registered_plugins": len(self.plugin_manager.get_all_plugins()),
            "total_vulnerabilities": total_vulnerabilities,
            "sessions_by_status": sessions_by_status
        }
        
        return stats
    
    def shutdown(self) -> None:
        """Shutdown the scanner engine."""
        self.logger.info("Shutting down scanner engine")
        
        # Cancel all active sessions
        for session_id in list(self.active_sessions.keys()):
            if self.get_session_status(session_id) == "running":
                self.cancel_session(session_id)
        
        # Cleanup plugins
        self.plugin_manager.cleanup_all()
        
        self.logger.info("Scanner engine shutdown complete")