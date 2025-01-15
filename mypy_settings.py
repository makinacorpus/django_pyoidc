from typing import Any

DJANGO_PYOIDC: dict[str, dict[str, Any]] = {}

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django_pyoidc",
]
