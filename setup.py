import os
import re

from setuptools import find_packages, setup


VERSION_RE = re.compile(r"__version__\s*=\s*\"(.*?)\"")
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args: str) -> str:
    """Reads complete file contents."""
    return open(os.path.join(HERE, *args), encoding="utf-8").read()


def get_version() -> str:
    """Reads the version from this module."""
    init = read("pygitguardian", "__init__.py")
    return VERSION_RE.search(init).group(1)  # type: ignore


setup(
    name="pygitguardian",
    version=get_version(),
    packages=find_packages(exclude=["tests"]),
    description="Python Wrapper for GitGuardian's API -- Scan security "
    "policy breaks everywhere",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/GitGuardian/py-gitguardian",
    author="GitGuardian",
    author_email="support@gitguardian.com",
    maintainer="GitGuardian",
    install_requires=[
        "marshmallow>=3.5, <4",
        "requests>=2, <3",
        "marshmallow-dataclass >=8.5.8, <8.6.0",
    ],
    include_package_data=True,
    zip_safe=True,
    license="MIT",
    keywords="api-client devsecops secrets-detection security-tools library gitguardian",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
