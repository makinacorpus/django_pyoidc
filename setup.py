#!/usr/bin/env python


import os

from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, "README.md")) as readme_file, open(
    os.path.join(HERE, "CHANGES.md")
) as changes_file, open(
    os.path.join(HERE, "makina_django_oidc", "VERSION")
) as version_file:
    README = readme_file.read()
    CHANGES = changes_file.read()
    VERSION = version_file.read().strip()

# from distutils.core import setup

setup(
    name="makina-django-oidc",
    version="0.1",
    description="Makina Django OIDC",
    author="Makina Corpus",
    author_email="makina_django_oidc@makina-corpus.net",
    url="https://gitlab.makina-corpus.net/pfl/makina-django-oidc",
    python_requires=">=3.7",
    packages=find_packages(),
    install_requires=["oic>=1.5.0", "django>=3.2", "jsonpickle"],
)
