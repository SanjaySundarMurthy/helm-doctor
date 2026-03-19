"""Setup configuration for helm-doctor."""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="helm-doctor",
    version="1.0.0",
    author="Sai Sandeep",
    author_email="ssan@example.com",
    description="The ultimate Helm chart linter, validator & security scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ssan/helm-doctor",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "jsonschema>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "helm-doctor=helm_doctor.cli:main",
        ],
    },
    keywords="helm kubernetes linter validator security scanner devops",
)
