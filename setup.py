#!/usr/bin/env python3
from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="qsafe",
    version="1.1.0",
    author="Miles Thompson",
    author_email="miles@overseerclaw.uk",
    description="Is your code quantum-safe? Scan any codebase for quantum-vulnerable cryptography. Grade A+ to F.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Miles0sage/quantum-mcp",
    py_modules=["pqc_posture", "pqc_scan_cli", "ast_analyzer", "auto_fix", "tls_scanner", "html_report"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "qsafe=pqc_scan_cli:main",
            "pqc-scan=pqc_scan_cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="quantum-safe cryptography security scanner pqc nist migration qsafe auto-fix cbom sarif",
    project_urls={
        "Bug Reports": "https://github.com/Miles0sage/quantum-mcp/issues",
        "Source": "https://github.com/Miles0sage/quantum-mcp",
    },
)
