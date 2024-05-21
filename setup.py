#!/usr/bin/env python


import os

from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, "django_pyoidc", "VERSION")) as version_file:
    VERSION = version_file.read().strip()

# from distutils.core import setup

setup(
    name="django-pyoidc",
    version=VERSION,
    description="Authenticate your users using OpenID Connect (OIDC)",
    author="Makina Corpus",
    author_email="django_pyoidc@makina-corpus.net",
    url="https://gitlab.makina-corpus.net/pfl/django-pyoidc",
    python_requires=">=3.7",
    packages=find_packages(),
    install_requires=[
        "oic==1.6.0",
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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    keywords="openid oidc django sso single-sign-on openid-connect",
    extras_require={
        "dev": [
            "python-decouple",
            "psycopg2",
            "sphinx<7",
            "sphinx_rtd_theme",
            "sphinx-autobuild",
            "isort",
            "pre-commit",
            "selenium",
        ]
    },
)
