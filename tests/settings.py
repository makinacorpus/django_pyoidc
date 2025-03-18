import os

from decouple import config

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.dirname(PROJECT_DIR)

SECRET_KEY = "fake-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "tests",
    "django_pyoidc",
]

ALLOWED_HOSTS = ["test.django-pyoidc.notatld", "test2.django-pyoidc.notatld"]

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
        "HOST": config("POSTGRES_HOST", "127.0.0.1"),
        "USER": config("POSTGRES_USER", "postgres"),
        "NAME": config("POSTGRES_DB", "postgres"),
        "PASSWORD": config("POSTGRES_PASSWORD", "postgres"),
        "PORT": config("POSTGRES_PORT", default=5432),
    }
}


ROOT_URLCONF = "tests.urls"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

DJANGO_PYOIDC = {
    "sso10": {
        "OIDC_CACHE_PROVIDER_METADATA": False,
        "client_id": "10",
        "client_secret": "--",
        "callback_uri_name": "op10_namespace:sso10-callback",
        "cache_django_backend": "default",
        "provider_discovery_uri": "http://sso10/uri/.well-known/openid-configuration",
        "login_uris_redirect_allowed_hosts": ["test.django-pyoidc.notatld"],
    },
    "sso11": {
        "OIDC_CACHE_PROVIDER_METADATA": False,
        "client_id": "11",
        "client_secret": "--",
        "oidc_paths_prefix": "oidc11",
        "cache_django_backend": "default",
        "provider_discovery_uri": "http://sso11/uri/.well-known/openid-configuration",
        "login_uris_redirect_allowed_hosts": ["test.django-pyoidc.notatld"],
    },
    "sso12": {
        "OIDC_CACHE_PROVIDER_METADATA": False,
        "client_id": "12",
        "client_secret": "--",
        "oidc_paths_prefix": "oidc12-zz",
        "oidc_callback_path": "prefix12/oidc12-zz-callback",
        "cache_django_backend": "default",
        "provider_discovery_uri": "http://sso12/uri/.well-known/openid-configuration",
        "login_uris_redirect_allowed_hosts": ["test.django-pyoidc.notatld"],
    },
    "sso13": {
        "OIDC_CACHE_PROVIDER_METADATA": False,
        "client_id": "13",
        "client_secret": "--",
        "callback_uri_name": "op13_namespace:sso13-callback",
        "oidc_paths_prefix": "oidc13-ww",
        "cache_django_backend": "default",
        "provider_discovery_uri": "http://sso12/uri/.well-known/openid-configuration",
        "login_uris_redirect_allowed_hosts": ["test.django-pyoidc.notatld"],
    },
}
