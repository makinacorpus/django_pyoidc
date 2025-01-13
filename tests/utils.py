import logging

from django.test import TestCase, override_settings

logger = logging.getLogger(__name__)


@override_settings(
    DJANGO_PYOIDC={
        "sso1": {
            "OIDC_CACHE_PROVIDER_METADATA": False,
            "client_id": "1",
            "client_secret": "--",
            "cache_django_backend": "default",
            "provider_class": "KeycloakProvider",
            "keycloak_base_uri": "http://sso1",
            "keycloak_realm": "realm1",
            "callback_uri_name": "my_test_callback",
            "post_login_uri_success": "/default/success",
            "login_uris_redirect_allowed_hosts": ["test.django-pyoidc.notatld"],
            "login_redirection_requires_https": True,
            "post_logout_redirect_uri": "/logoutdone",
            "post_login_uri_failure": "/logout_failure",
            "use_introspection_on_access_tokens": False,
        },
        "sso2": {
            "OIDC_CACHE_PROVIDER_METADATA": False,
            "client_id": "2",
            "client_secret": "--",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://sso2/uri",
            "login_uris_redirect_allowed_hosts": ["test2.django-pyoidc.notatld"],
            "oidc_callback_path": "/callback-wtf/",
            "hook_validate_access_token": "tests.e2e.test_app.callback:hook_validate_access_token",
        },
        "sso3": {
            "oidc_cache_provider_metadata": True,
            "client_id": "3",
            "client_secret": "--",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://sso3/uri",
        },
        "sso4": {
            "OIDC_CACHE_PROVIDER_METADATA": True,
            "client_id": "4",
            "client_secret": "--",
            "cache_django_backend": "default",
            "provider_discovery_uri": "http://sso4/uri/.well-known/openid-configuration",
        },
        "drf": {
            "OIDC_CACHE_PROVIDER_METADATA": False,
            "client_id": "drf-api",
            "client_secret": "--",
            "provider_discovery_uri": "http://sso5/uri/.well-known/openid-configuration",
        },
    }
)
class OIDCTestCase(TestCase):
    pass
