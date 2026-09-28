from setuptools import setup, find_packages

setup(
    name="pixellance",
    version="0.2.0",
    description="Port-triggered pentest orchestration framework (HexStrike backend)",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28",
    ],
    entry_points={
        "console_scripts": [
            "pixellance=pixellance.cli:main",
        ],
    },
)
