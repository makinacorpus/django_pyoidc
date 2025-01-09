import logging

from django.test import TestCase, override_settings

logger = logging.getLogger(__name__)


@override_settings(
    DJANGO_PYOIDC={
        "sso1": {
            "OIDC_CACHE_PROVIDER_METADATA": False,
            "client_id": "1",
            "cache_django_backend": "default",
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://sso1",
            "keycloak_realm": "realm1",
            "client_secret": "",
            "callback_uri_name": "my_test_callback",
            "post_login_uri_success": "/default/success",
            "login_uris_redirect_allowed_hosts": ["test.django-pyoidc.notatld"],
            "login_redirection_requires_https": True,
            "post_logout_redirect_uri": "/logoutdone",
            "post_login_uri_failure": "/logout_failure",
        },
        "sso2": {
            "OIDC_CACHE_PROVIDER_METADATA": False,
            "client_id": "2",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://sso2/uri",
            "login_uris_redirect_allowed_hosts": ["test2.django-pyoidc.notatld"],
            "client_secret": "",
            "oidc_callback_path": "/callback-wtf/",
        },
        "sso3": {
            "oidc_cache_provider_metadata": True,
            "client_id": "3",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://sso3/uri",
            "client_secret": "",
        },
        "sso4": {
            "OIDC_CACHE_PROVIDER_METADATA": True,
            "client_id": "4",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://sso4/uri/.well-known/openid-configuration",
            "client_secret": "",
        },
    }
)
class OIDCTestCase(TestCase):
    pass
