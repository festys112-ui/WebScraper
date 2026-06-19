from setuptools import setup, find_packages

setup(
    name="web-security-crawler",
    version="1.0.0",
    description="A real-time web crawler that labels websites by security protocol",
    author="CursBNR Security Tools",
    py_modules=["crawler"],
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "colorama>=0.4.6",
        "lxml>=4.9.0",
    ],
    entry_points={
        "console_scripts": [
            "web-crawler=crawler:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
    ],
)
