#!/usr/bin/env python3
"""
Main entry point for the vulnerability scanner.
"""
import sys
from pathlib import Path

import cli

if __name__ == '__main__':
    sys.exit(cli.main())