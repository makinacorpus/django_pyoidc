import os

from decouple import config

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.dirname(PROJECT_DIR)

SECRET_KEY = "fake-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "tests_e2e.test_app",
    "django_pyoidc",
]

ALLOWED_HOSTS = ["test.django-pyoidc.notatld"]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(PROJECT_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
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
    "test": {
        "OIDC_CALLBACK_PATH": "/callback",
        "OIDC_CLIENT_SECRET": "EnSAdFDlM78HejQ5EQATtlvXgRzfNww4",
        "OIDC_CLIENT_ID": "full",
        "OIDC_PROVIDER_DISCOVERY_URI": "http://oidc.test/auth/realms/Demo",
        "POST_LOGIN_URI_FAILURE": "http://oidc.test/",
        "POST_LOGOUT_REDIRECT_URI": "http://oidc.test/",
        "POST_LOGIN_URI_SUCCESS": "http://oidc.test/",
        "LOGIN_REDIRECTION_REQUIRES_HTTPS": False,
        "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["oidc.test"],
        "SCOPE": "full-dedicated",
        "CACHE_DJANGO_BACKEND": "default",
    }
}


ROOT_URLCONF = "tests_e2e.urls"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}
