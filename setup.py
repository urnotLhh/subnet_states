from setuptools import setup, find_packages

setup(
    name="subnet_states",
    version="1.0.0",
    description="子网状态评估与扫描速率决策策略模块",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.21.0",
        "networkx>=2.6.0",
        "click>=8.0.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "subnet_states=src.main:main",
        ],
    },
    python_requires=">=3.7",
)
