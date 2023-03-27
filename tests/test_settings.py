from decouple import config

SECRET_KEY = "fake-key"
INSTALLED_APPS = ["tests", "makina_django_oidc"]

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
