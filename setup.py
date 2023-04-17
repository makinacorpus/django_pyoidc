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
    description="Authenticate your users using OpenID Connect (OIDC)",
    author="Makina Corpus",
    author_email="makina_django_oidc@makina-corpus.net",
    url="https://gitlab.makina-corpus.net/pfl/makina-django-oidc",
    python_requires=">=3.7",
    packages=find_packages(),
    install_requires=[
        "oic@git+https://github.com/CZ-NIC/pyoidc@444bd6845e13b06c14fbaefccbc0c47059aa2364",
        "django>=3.2",
        "jsonpickle",
        "jwt",
    ],
    classifiers=[
        "Topic :: Utilities",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    keywords="openid oidc django sso single-sign-on openid-connect",
    extras_require={"dev": ["python-decouple", "psycopg2"]},
)
