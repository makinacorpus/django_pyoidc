#!/usr/bin/env python


import os

from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, "django_pyoidc", "VERSION")) as version_file:
    VERSION = version_file.read().strip()

setup(
    version=VERSION,
    packages=find_packages(),
)
