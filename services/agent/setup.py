from setuptools import setup, find_packages

setup(
    name="secai-agent",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "flask>=2.0",
        "requests",
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "secai-agent=agent.app:main",
        ],
    },
)
