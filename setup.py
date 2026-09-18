# setup.py
from setuptools import setup, find_packages

setup(
    name="pathasm",
    version="1.0.0",
    description="Context-Aware Graph Threat Modeling & Active Directory Evasion Engine",
    author="Dhruv",
    # Registers the root main.py file so it installs along with the package package framework
    py_modules=["main"],
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "networkx>=3.0",
        "streamlit>=1.30.0",
        "pyvis>=0.3.2",
        "ldap3>=2.9.1",
        "click>=8.1.0",
        "reportlab>=4.0.0"
    ],
    entry_points={
        "console_scripts": [
            # Aligns the executable command launcher directly to your main function inside main.py
            "pathasm=main:main",
        ],
    },
    python_requires=">=3.8",
)

