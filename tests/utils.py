import logging

from django.test import TestCase, override_settings

logger = logging.getLogger(__name__)


@override_settings(
    DJANGO_PYOIDC={
        "sso1": {
            "OIDC_CACHE_PROVIDER_METADATA": False,
            "OIDC_CLIENT_ID": "1",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "",
            "OIDC_CLIENT_SECRET": "",
            "OIDC_CALLBACK_PATH": "/callback",
            "POST_LOGIN_URI_SUCCESS": "/default/success",
            "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["test.django-pyoidc.notatld"],
            "LOGIN_REDIRECTION_REQUIRES_HTTPS": True,
            "POST_LOGOUT_REDIRECT_URI": "/logoutdone",
            "POST_LOGIN_URI_FAILURE": "/logout_failure",
        },
        "sso2": {
            "OIDC_CACHE_PROVIDER_METADATA": False,
            "OIDC_CLIENT_ID": "2",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "",
            "OIDC_CLIENT_SECRET": "",
        },
        "sso3": {
            "OIDC_CACHE_PROVIDER_METADATA": True,
            "OIDC_CLIENT_ID": "3",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "http://sso3/uri",
            "OIDC_CLIENT_SECRET": "",
        },
        "sso4": {
            "OIDC_CACHE_PROVIDER_METADATA": True,
            "OIDC_CLIENT_ID": "4",
            "CACHE_DJANGO_BACKEND": "default",
            "OIDC_PROVIDER_DISCOVERY_URI": "http://sso4/uri",
            "OIDC_CLIENT_SECRET": "",
        },
    }
)
class OIDCTestCase(TestCase):
    pass
