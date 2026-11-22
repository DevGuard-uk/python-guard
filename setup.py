#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="devguard-python-guard",
    version="1.0.1",
    description="DevGuard zero-dependency anti-theft, domain authorization, and milestone autolock guard for FastAPI, Django, and Flask.",
    long_description=open("README.md", "r", encoding="utf-8").read() if open("README.md").readable() else "",
    long_description_content_type="text/markdown",
    author="DevGuard Security Team",
    author_email="security@devguard.uk",
    url="https://devguard.uk",
    packages=find_packages(),
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Framework :: FastAPI",
        "Framework :: Django",
        "Framework :: Flask",
    ],
    python_requires=">=3.7",
    install_requires=[],
)
