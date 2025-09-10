from setuptools import setup, find_packages
import pathlib

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text(encoding="utf-8")

setup(
    name="crlfhunter",
    version="1.0.0",
    description="High-coverage CRLF injection & h2 smuggling scanner with optional Web UI",
    long_description=README,
    long_description_content_type="text/markdown",
    author="DeathReaper",
    license="MIT",
    url="https://github.com/DeathReaper/crlfhunter",
    packages=find_packages(exclude=("tests", "examples")),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "httpx>=0.27.0",
        "h2>=4.1.0",
        "fastapi>=0.115.0",
        # 'uvicorn' optional extra 'standard' pulls in httptools and uvloop, which may not be available
        # in offline environments. Use the base package instead.
        "uvicorn>=0.30.0",
        # python-multipart is required for file uploads in the web UI. It is
        # optional here because some offline environments cannot install it.
    ],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "crlfhunter=crlfhunter.cli:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Environment :: Console",
    ],
)