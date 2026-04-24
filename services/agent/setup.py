from setuptools import setup, find_packages

setup(
    name="secai-agent",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "flask==3.1.3",
        "requests==2.33.1",
        "pyyaml==6.0.3",
    ],
    entry_points={
        "console_scripts": [
            "secai-agent=agent.app:main",
        ],
    },
)
