from decouple import config

SECRET_KEY = "fake-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "tests",
    "django_pyoidc",
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
DJANGO_PYOIDC = {
    "client1": {
        "PROVIDER_URI": "http://oidc.test/auth/realms/Demo",
        "REDIRECT_URI": "http://oidc.test/callback",
        "OIDC_CLIENT_SECRET": "EnSAdFDlM78HejQ5EQATtlvXgRzfNww4",
        "OICD_CLIENT_ID": "full",
        "REDIRECT_FAILURE_URI": "http://oidc.test/",
        "REDIRECT_LOGOUT_URI": "http://oidc.test/",
        "LOGIN_REDIRECT_SUCCESS_DEFAULT_URI": "http://oidc.test/",
        "LOGIN_ENABLE_REDIRECT_REQUIRES_HTTPS": False,
        "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["oidc.test"],
        "SCOPE": "full-dedicated",
        "CACHE_DJANGO_BACKEND": "default",
    }
}


ROOT_URLCONF = "tests.urls"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}
