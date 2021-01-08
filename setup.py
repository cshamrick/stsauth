import re
import os
from setuptools import setup, find_packages


def get_requirements(env=""):
    path = os.path.dirname(os.path.abspath(__file__))
    fn = "requirements{}{}.txt".format(("-" if env else ""), env)
    fp = os.path.join(path, fn)
    if os.path.exists(fp):
        with open(fp, "r") as reqs:
            return [x.strip() for x in reqs.read().split("\n") if not x.startswith("#")]
    else:
        return []


with open("sts_auth/__init__.py", "r", encoding="utf8") as f:
    version = re.search(r'__version__ = "(.*?)"', f.read()).group(1)


long_description = ""
if os.path.exists("README.md"):
    with open("README.md", "r") as fh:
        long_description = fh.read()

install_requires = get_requirements()
tests_require = get_requirements("test")

setup(
    name="stsauth",
    version=version,
    author="Scott Hamrick",
    author_email="scott@scotthamrick.com",
    description="CLI tool for fetching AWS tokens.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cshamrick/stsauth",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: OS Independent",
    ],
    install_requires=install_requires,
    tests_require=tests_require,
    entry_points="""
        [console_scripts]
        stsauth=sts_auth.cli:cli
    """,
    license="MIT",
)
