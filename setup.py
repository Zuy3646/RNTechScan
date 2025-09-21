#!/usr/bin/env python3
"""
Скрипт установки для сканера уязвимостей.
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    requirements = []
    with open(requirements_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Remove version constraints for basic requirements
                if '>=' in line:
                    req = line.split('>=')[0]
                else:
                    req = line
                requirements.append(req)
else:
    requirements = ['requests', 'PyYAML']

setup(
    name="RNTechScan",
    version="1.0.0",
    author="RNTechScan Team",
    author_email="contact@rntechscan.com",
    description="RNTechScan - Расширенный модульный сканер уязвимостей",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rntechscan/RNTechScan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
        "enhanced": [
            "colorama>=0.4.5",
            "tqdm>=4.64.0",
            "click>=8.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "rntechscan=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.txt", "*.md"],
    },
    zip_safe=False,
    keywords="vulnerability scanner security network web system",
    project_urls={
        "Bug Reports": "https://github.com/rntechscan/RNTechScan/issues",
        "Source": "https://github.com/rntechscan/RNTechScan",
        "Documentation": "https://rntechscan.readthedocs.io/",
    },
)