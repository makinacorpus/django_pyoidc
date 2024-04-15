from django.test import TestCase, override_settings


@override_settings(
    DJANGO_PYOIDC={
        "sso1": {
            "OIDC_CLIENT_ID": "1",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "",
            "OIDC_CLIENT_SECRET": "",
            "OIDC_CALLBACK_PATH": "/callback",
            "POST_LOGIN_URI_SUCCESS_DEFAULT": "/default/success",
            "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["test.django-pyoidc.notatld"],
            "LOGIN_ENABLE_REDIRECT_REQUIRES_HTTPS": True,
            "POST_LOGOUT_REDIRECT_URI": "/logoutdone",
            "POST_LOGIN_URI_FAILURE": "/logout_failure",
        },
        "sso2": {
            "OIDC_CLIENT_ID": "2",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "",
            "OIDC_CLIENT_SECRET": "",
        },
    }
)
class OIDCTestCase(TestCase):
    pass
