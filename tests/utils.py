from django.test import TestCase, override_settings


@override_settings(
    MAKINA_DJANGO_OIDC={
        "client1": {
            "CLIENT_ID": "1",
            "CACHE_BACKEND": "default",
            "URI_PROVIDER": "",
            "URI_CONFIG": "",
            "CLIENT_SECRET": "",
            "CALLBACK_PATH": "/callback",
            "URI_DEFAULT_SUCCESS": "/default/success",
            "REDIRECT_ALLOWED_HOSTS": ["test.makina-django-oidc.notatld"],
            "REDIRECT_REQUIRES_HTTPS": True,
            "URI_LOGOUT": "/logoutdone",
        },
        "client2": {
            "CLIENT_ID": "2",
            "CACHE_BACKEND": "default",
            "URI_PROVIDER": "",
            "URI_CONFIG": "",
            "CLIENT_SECRET": "",
        },
    }
)
class OIDCTestCase(TestCase):
    pass
