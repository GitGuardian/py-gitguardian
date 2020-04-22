import re
from os.path import abspath, dirname, join

from setuptools import find_packages, setup


VERSION_RE = re.compile(r"__version__\s*=\s*\"(.*?)\"")


def readme():
    with open(abspath("README.md")) as f:
        return f.read()


current_path = abspath(dirname(__file__))

with open(join(current_path, "pygitguardian", "__init__.py")) as file:
    content = file.read()
    result = re.search(VERSION_RE, content)
    if result is None:
        raise Exception("could not find package version")
    __version__ = result.group(1)

setup(
    name="pygitguardian",
    version=__version__,
    packages=find_packages(exclude=["tests"]),
    description=readme(),
    install_requires=["marshmallow", "requests"],
    include_package_data=True,
    author="GitGuardian",
    author_email="support@gitguardian.com",
    zip_safe=True,
)
