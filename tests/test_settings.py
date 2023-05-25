from decouple import config

SECRET_KEY = "fake-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "tests",
    "makina_django_oidc",
]

ALLOWED_HOSTS = ["test.django-pyoidc.notatld"]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

# SESSION_ENGINE = "django.contrib.sessions.backends.file"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": config("POSTGRES_HOST", "db"),
        "USER": config("POSTGRES_USER", "postgres"),
        "NAME": config("POSTGRES_DB", "postgres"),
        "PASSWORD": config("POSTGRES_PASSWORD", "postgres"),
        "PORT": config("POSTGRES_PORT", default=5432),
    }
}
MAKINA_DJANGO_OIDC = {
    "test": {
        "PROVIDER_URI": "http://oidc.test/",
        "REDIRECT_URI": "http://oidc.test/callback",
        "CLIENT_SECRET": "EnSAdFDlM78HejQ5EQATtlvXgRzfNww4",
        "CLIENT_ID": "full",
        "CONFIG_URI": "/auth/realms/Demo",
        "REDIRECT_FAILURE_URI": "http://oidc.test/",
        "REDIRECT_LOGOUT_URI": "http://oidc.test/",
        "REDIRECT_SUCCESS_DEFAULT_URI": "http://oidc.test/",
        "REDIRECT_REQUIRES_HTTPS": False,
        "REDIRECT_ALLOWED_HOSTS": ["oidc.test"],
        "SCOPE": "full-dedicated",
        "CACHE_BACKEND": "default",
    }
}


ROOT_URLCONF = "tests.urls"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}
