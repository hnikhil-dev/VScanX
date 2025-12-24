"""
Setup configuration for VScanX
"""

import re
from pathlib import Path

from setuptools import find_packages, setup

version_file = Path(__file__).parent / "core" / "config.py"
VERSION = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', version_file.read_text(), re.M).group(1)

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = (
    readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""
)

setup(
    name="vscanx",
    version=VERSION,
    description="Ethical Vulnerability Scanner - Modular Security Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="VScanX Contributors",
    author_email="security@example.com",  # Update with real contact
    url="https://github.com/yourusername/vscanx",  # Update with real repo
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    packages=find_packages(exclude=["tests", "tests.*", "*.tests", "*.tests.*"]),
    install_requires=[
        "requests>=2.31.0",
        "scapy>=2.5.0",
        "jinja2>=3.1.2",
        "jsonschema>=4.19.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "ruff>=0.1.0",
        ],
        "pdf": [
            "reportlab>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vscanx=vscanx:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="security vulnerability scanner ethical pentesting",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/vscanx/issues",  # Update
        "Source": "https://github.com/yourusername/vscanx",  # Update
        "Documentation": "https://github.com/yourusername/vscanx/blob/main/README.md",  # Update
    },
)
