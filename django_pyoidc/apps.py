from django.apps import AppConfig


class DjangoPyoidcConfig(AppConfig):
    name = "django_pyoidc"

    def ready(self) -> None:
        # Register schema with drf_spectacular
        from .drf import schema  # noqa: F401
