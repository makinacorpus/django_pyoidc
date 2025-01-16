from typing import Any, Dict

DJANGO_PYOIDC: Dict[str, Dict[str, Any]] = {}

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django_pyoidc",
]
