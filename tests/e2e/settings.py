import os

from decouple import config

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.dirname(PROJECT_DIR)

SECRET_KEY = "fake-key"
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "rest_framework",
    "corsheaders",
    "tests.e2e.test_app",
    "django_pyoidc",
]

ALLOWED_HOSTS = ["test.django-pyoidc.notatld", "testserver", "localhost"]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
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

# DJANGO_PYOIDC settings are defined here and not in tests overrides
# if we need to use the OIDCHelper.get_urlpatterns() function
DJANGO_PYOIDC = {
    "lemon1": {
        "provider_class": "LemonLDAPng2Provider",
        "client_id": "app1",
        "cache_django_backend": "default",
        "provider_discovery_uri": "http://localhost:8070/",
        "client_secret": "secret_app1",
        "callback_uri_name": "lemon1_namespace:lemon1-callback",
        "post_logout_redirect_uri": "/test-ll-logout-done-1",
        "login_uris_redirect_allowed_hosts": ["testserver"],
        "login_redirection_requires_https": False,
        "post_login_uri_success": "/test-ll-success-1",
        "post_login_uri_failure": "/test-ll-failure-1",
        "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
        "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
        # "oidc_logout_query_string_extra_parameters_dict": {"confirm": 1},
    },
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "django_pyoidc.drf.authentication.OIDCBearerAuthentication",
    ],
    # Use Django's standard `django.contrib.auth` permissions,
    # or allow read-only access for unauthenticated users.
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.DjangoModelPermissions"],
}

CORS_ALLOWED_ORIGINS = [
    "http://localhost:9999",
]

ROOT_URLCONF = "tests.e2e.urls"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}
