#!/usr/bin/env python3
"""
Main entry point for the vulnerability scanner.
"""
import sys
from pathlib import Path

# Add the scanner directory to the Python path
scanner_dir = Path(__file__).parent
sys.path.insert(0, str(scanner_dir))

import cli

if __name__ == '__main__':
    sys.exit(cli.main())