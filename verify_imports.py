#!/usr/bin/env python3
"""
Simple test script to verify all imports work correctly after cleanup.
"""

def test_core_imports():
    """Test core module imports."""
    try:
        from core.plugin_base import BasePlugin, ScanTarget, ScanResult, Vulnerability, SeverityLevel
        from core.scanner import ScanEngine
        from core.task_manager import TaskManager
        from core.database.cve_manager import CVEDatabase
        print("✅ Core modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Core import failed: {e}")
        return False

def test_config_imports():
    """Test configuration module imports."""
    try:
        from config.settings import get_config, Config
        from config.logging_config import get_logger, setup_logging
        print("✅ Config modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Config import failed: {e}")
        return False

def test_module_imports():
    """Test scanner module imports."""
    try:
        from modules.network.port_scanner import PortScannerPlugin
        from modules.web.web_scanner import WebVulnScannerPlugin
        from modules.system.system_scanner import SystemVulnScannerPlugin
        from modules.exploits.active_tester import ActiveVulnerabilityTester
        from modules.exploits.chain_analyzer import AttackChainAnalyzer
        from modules.cve_detector import CVEVulnerabilityDetector
        print("✅ Scanner modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Scanner module import failed: {e}")
        return False

def test_reports_imports():
    """Test reports module imports."""
    try:
        from reports.report_generator import ReportManager
        print("✅ Reports module imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Reports import failed: {e}")
        return False

def test_main_imports():
    """Test main CLI imports."""
    try:
        import cli
        import main
        print("✅ Main CLI modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Main CLI import failed: {e}")
        return False

def main():
    """Run all import tests."""
    print("🚀 RNTechScan Import Verification (After Cleanup)")
    print("=" * 60)
    
    tests = [
        test_core_imports,
        test_config_imports,
        test_module_imports,
        test_reports_imports,
        test_main_imports
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"🎯 RESULT: {passed}/{total} import tests passed")
    
    if passed == total:
        print("✅ All imports working correctly after cleanup!")
        return 0
    else:
        print("❌ Some imports still failing")
        return 1

if __name__ == "__main__":
    exit(main())