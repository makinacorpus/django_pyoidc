from importlib import import_module
from unittest import mock

from django.conf import settings
from django.test import override_settings

from django_pyoidc.client import OIDCClient
from django_pyoidc.exceptions import InvalidOIDCConfigurationException
from tests.utils import OIDCTestCase

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


class SettingsTestCase(OIDCTestCase):
    @override_settings(
        DJANGO_PYOIDC={
            "lib_123": {
                "oidc_cache_provider_metadata": False,
                "oidc_cache_provider_metadata_ttl": 75,
                "client_id": "foo",
                "client_secret": "secret_app_foo",
                "cache_django_backend": "default",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "keycloak_base_uri": "http://sso_tutut",
                "keycloak_realm": "realm_foo",
                "oidc_callback_path": "/callback-foo-abc",
                "login_uris_redirect_allowed_hosts": ["foo", "bar"],
                "login_redirection_requires_https": True,
                "post_login_uri_success": "/abc-123",
                "post_login_uri_failure": "/def-456",
                "post_logout_redirect_uri": "/ghj-789",
                "hook_user_login": "tests.e2e.test_app.callback:login_callback",
                "hook_user_logout": "tests.e2e.test_app.callback:logout_callback",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_extracted_from_django_pyoidc_settings(
        self, mocked_provider_config, *args
    ):
        """
        Test that definitions of DJANGO_PYOIDC in settings can be retrieved in client settings.
        """
        sso_client = OIDCClient(op_name="lib_123")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("client_id"), "foo")
        self.assertEqual(settings.get("client_secret"), "secret_app_foo")
        self.assertEqual(
            settings.get("provider_discovery_uri"), "http://sso_tutut/realms/realm_foo"
        )
        self.assertEqual(settings.get("cache_django_backend"), "default")
        self.assertEqual(settings.get("oidc_cache_provider_metadata"), False)
        self.assertEqual(settings.get("oidc_cache_provider_metadata_ttl"), 75)
        self.assertEqual(settings.get("oidc_callback_path"), "/callback-foo-abc")
        self.assertEqual(
            settings.get("login_uris_redirect_allowed_hosts"), ["foo", "bar"]
        )
        self.assertEqual(settings.get("login_redirection_requires_https"), True)
        self.assertEqual(settings.get("post_login_uri_success"), "/abc-123")
        self.assertEqual(settings.get("post_login_uri_failure"), "/def-456")
        self.assertEqual(settings.get("post_logout_redirect_uri"), "/ghj-789")
        self.assertEqual(
            settings.get("hook_user_login"),
            "tests.e2e.test_app.callback:login_callback",
        )
        self.assertEqual(
            settings.get("hook_user_logout"),
            "tests.e2e.test_app.callback:logout_callback",
        )

    @override_settings(
        DJANGO_PYOIDC={
            "lib_238": {
                "oidc_cache_provider_metadata": False,
                "client_id": "foo2",
                "provider_discovery_uri": "http://foo",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_defaults(self, mocked_provider_config, *args):
        """
        Test that minimal definitions of DJANGO_PYOIDC still get some default settings.
        """
        sso_client = OIDCClient(op_name="lib_238")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("client_id"), "foo2")
        # useful if bad public client is used
        self.assertEqual(settings.get("client_secret"), None)
        self.assertEqual(settings.get("provider_discovery_uri"), "http://foo")
        self.assertEqual(settings.get("cache_django_backend"), "default")
        self.assertEqual(settings.get("oidc_cache_provider_metadata"), False)
        self.assertEqual(settings.get("oidc_cache_provider_metadata_ttl"), 120)
        self.assertEqual(settings.get("login_redirection_requires_https"), True)
        self.assertEqual(settings.get("post_login_uri_success"), "/")
        self.assertEqual(settings.get("post_login_uri_failure"), "/")
        self.assertEqual(settings.get("post_logout_redirect_uri"), "/")
        self.assertEqual(settings.get("oidc_callback_path"), "/oidc-callback/")
        self.assertEqual(settings.get("login_uris_redirect_allowed_hosts"), None)
        self.assertEqual(settings.get("hook_user_login"), None)
        self.assertEqual(settings.get("hook_user_logout"), None)
        self.assertEqual(settings.get("hook_validate_access_token"), None)
        self.assertEqual(settings.get("use_introspection_on_access_tokens"), False)

    @override_settings(
        DJANGO_PYOIDC={
            "lib_314": {
                "oidc_cache_provider_metadata": False,
                "client_id": "foo3",
                "client_secret": "secret",
                "provider_discovery_uri": "http://foo",
                "callback_uri_name": "my_test_callback",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_callback_uri_name_to_oidc_callback_path(
        self, mocked_provider_config, *args
    ):
        """
        Test that we can give a named route in callback_uri_name instead of giving oidc_callback_path.
        """
        sso_client = OIDCClient(op_name="lib_314")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("callback_uri_name"), None)
        self.assertEqual(settings.get("oidc_callback_path"), "/callback-xyz/")

    @override_settings(
        DJANGO_PYOIDC={
            "lib_315": {
                "oidc_cache_provider_metadata": False,
                "client_id": "foo3",
                "client_secret": "secret",
                "provider_discovery_uri": "http://foo",
                "CALLBACK_URI_NAME": "my_test_callback",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_callback_uri_name_to_oidc_callback_path_upper(
        self, mocked_provider_config, *args
    ):
        """
        Test that we can give a named route in callback_uri_name instead of giving oidc_callback_path.
        """
        sso_client = OIDCClient(op_name="lib_315")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("callback_uri_name"), None)
        self.assertEqual(settings.get("CALLBACK_URI_NAME"), None)
        self.assertEqual(settings.get("oidc_callback_path"), "/callback-xyz/")

    @override_settings(
        DJANGO_PYOIDC={
            "lib_318": {
                "oidc_cache_provider_metadata": False,
                "client_id": "foo4",
                "client_secret": "secret",
                "provider_discovery_uri": "http://foo",
                "logout_redirect": "/zorg-1",
                "failure_redirect": "/zorg-2",
                "success_redirect": "/zorg-3",
                "redirect_requires_https": False,
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_aliases(self, mocked_provider_config, *args):
        """
        Test that minimal definitions of DJANGO_PYOIDC still get some default settings.
        """
        sso_client = OIDCClient(op_name="lib_318")
        settings = sso_client.get_settings()
        # Aliases
        # logout_redirect -> post_logout_redirect_uri
        self.assertEqual(settings.get("logout_redirect"), None)
        self.assertEqual(settings.get("post_logout_redirect_uri"), "/zorg-1")
        # failure_redirect -> post_login_uri_failure
        self.assertEqual(settings.get("failure_redirect"), None)
        self.assertEqual(settings.get("post_login_uri_failure"), "/zorg-2")
        # success_redirect -> post_login_uri_success
        self.assertEqual(settings.get("success_redirect"), None)
        self.assertEqual(settings.get("post_login_uri_success"), "/zorg-3")
        # redirect_requires_https -> login_redirection_requires_https
        self.assertEqual(settings.get("redirect_requires_https"), None)
        self.assertEqual(settings.get("login_redirection_requires_https"), False)

    @override_settings(
        DJANGO_PYOIDC={
            "lib_319": {
                "oidc_cache_provider_metadata": False,
                "client_id": "foo4",
                "client_secret": "secret",
                "provider_discovery_uri": "http://foo",
                "LOGOUT_REDIRECT": "/zorg-1",
                "FAILURE_REDIRECT": "/zorg-2",
                "SUCCESS_REDIRECT": "/zorg-3",
                "REDIRECT_REQUIRES_HTTPS": False,
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_aliases_upper(self, mocked_provider_config, *args):
        """
        Test that minimal definitions of DJANGO_PYOIDC still get some default settings.
        """
        sso_client = OIDCClient(op_name="lib_319")
        settings = sso_client.get_settings()
        # Aliases
        # logout_redirect -> post_logout_redirect_uri
        self.assertEqual(settings.get("LOGOUT_REDIRECT"), None)
        self.assertEqual(settings.get("logout_redirect"), None)
        self.assertEqual(settings.get("post_logout_redirect_uri"), "/zorg-1")
        # failure_redirect -> post_login_uri_failure
        self.assertEqual(settings.get("failure_redirect"), None)
        self.assertEqual(settings.get("FAILURE_REDIRECT"), None)
        self.assertEqual(settings.get("post_login_uri_failure"), "/zorg-2")
        # success_redirect -> post_login_uri_success
        self.assertEqual(settings.get("success_redirect"), None)
        self.assertEqual(settings.get("SUCCESS_REDIRECT"), None)
        self.assertEqual(settings.get("post_login_uri_success"), "/zorg-3")
        # redirect_requires_https -> login_redirection_requires_https
        self.assertEqual(settings.get("redirect_requires_https"), None)
        self.assertEqual(settings.get("REDIRECT_REQUIRES_HTTPS"), None)
        self.assertEqual(settings.get("login_redirection_requires_https"), False)

    @override_settings(
        DJANGO_PYOIDC={
            "lib_371": {
                "oidc_cache_provider_metadata": False,
                "client_id": "foo3",
                "client_secret": "secret",
                "provider_discovery_uri": "http://foo",
                "callback_uri_name": "my_test_callback",
                "use_introspection_on_access_tokens": True,
                "hook_validate_access_token": "tests.e2e.test_app.callback:hook_validate_access_token",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_no_hook_validate_access_token_if_use_introspection_on_access_tokens(
        self, mocked_provider_config, *args
    ):
        """
        Test that we prevent setting using both use_introspection_on_access_tokens and hook_validate_access_token.
        """
        with self.assertRaises(InvalidOIDCConfigurationException) as context:
            OIDCClient(op_name="lib_371")
        self.assertTrue(
            "You cannot define hook_validate_access_token if you use use_introspection_on_access_tokens."
            in context.exception.__repr__()
        )

    @override_settings(
        DJANGO_PYOIDC={
            "lib_547": {
                "oidc_cache_provider_metadata": False,
                "client_secret": "secret_app_foo2",
                "provider_discovery_uri": "http://foo",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_missing_client_id(self, mocked_provider_config, *args):
        """
        Test that missing client_id will fail.
        """
        with self.assertRaises(InvalidOIDCConfigurationException) as context:
            OIDCClient(op_name="lib_547")
        self.assertTrue(
            "Provider definition does not contain any 'client_id' entry."
            in context.exception.__repr__()
        )

    @override_settings(
        DJANGO_PYOIDC={
            "lib_548": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_548",
                "client_secret": "secret",
            },
            "lib_549": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_549",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "keycloak_base_uri": "http://sso_tutut",
            },
            "lib_550": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_550",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "keycloak_realm": "toto",
            },
            "lib_551": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_551",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "provider_discovery_uri": "http://uvw/xyz/abc/",
            },
            "lib_552": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_552",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "provider_discovery_uri": "http://uvw/xyz/realms/",
            },
            "lib_553": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_552",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "provider_discovery_uri": "http://uvw/xyz/realms/foo/bar",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_missing_provider_discovery_uri(
        self, mocked_provider_config, *args
    ):
        """
        Test that missing provider_discovery_uri (or alternatives) will fail.
        """
        with self.assertRaises(InvalidOIDCConfigurationException) as context:
            OIDCClient(op_name="lib_548")
        self.assertTrue(
            "No provider discovery uri provided." in context.exception.__repr__()
        )
        with self.assertRaises(TypeError) as context:
            OIDCClient(op_name="lib_549")
        self.assertTrue(
            "Keycloak10Provider requires keycloak_base_uri and keycloak_realm or provider_discovery_uri."
            in context.exception.__repr__()
        )
        with self.assertRaises(TypeError) as context:
            OIDCClient(op_name="lib_550")
        self.assertTrue(
            "Keycloak10Provider requires keycloak_base_uri and keycloak_realm or provider_discovery_uri."
            in context.exception.__repr__()
        )
        with self.assertRaises(RuntimeError) as context:
            OIDCClient(op_name="lib_551")
        self.assertTrue(
            "Provided 'provider_discovery_uri' url is not a valid Keycloak metadata url, it does not contains /realms/."
            in context.exception.__repr__()
        )
        with self.assertRaises(RuntimeError) as context:
            OIDCClient(op_name="lib_552")
        self.assertTrue(
            "Provided 'provider_discovery_uri' url is not a valid Keycloak metadata url, it does not contains /realms/."
            in context.exception.__repr__()
        )
        with self.assertRaises(RuntimeError) as context:
            OIDCClient(op_name="lib_553")
        self.assertTrue(
            "Cannot extract the keycloak realm from the provided url."
            in context.exception.__repr__()
        )

    @override_settings(
        DJANGO_PYOIDC={
            "lib_612": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_612",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "keycloak_base_uri": "http://abc/def",
                "keycloak_realm": "ghj",
            },
            "lib_613": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_613",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "provider_discovery_uri": "http://lmn/opq/realms/rst",
            },
            "lib_614": {
                "oidc_cache_provider_metadata": False,
                "client_id": "lib_613",
                "client_secret": "secret",
                "provider_class": "django_pyoidc.providers.KeycloakProvider",
                "provider_discovery_uri": "http://uvw/xyz/realms/abc/.well-known/openid-configuration",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_keycloak_provider_can_generate_provider_discovery_uri_or_not(
        self, mocked_provider_config, *args
    ):
        """
        Test that missing provider_discovery_uri (or alternatives) will fail.
        """
        sso_client = OIDCClient(op_name="lib_612")
        settings = sso_client.get_settings()
        self.assertEqual(
            settings.get("provider_discovery_uri"), "http://abc/def/realms/ghj"
        )
        sso_client = OIDCClient(op_name="lib_613")
        settings = sso_client.get_settings()
        self.assertEqual(
            settings.get("provider_discovery_uri"), "http://lmn/opq/realms/rst"
        )
        sso_client = OIDCClient(op_name="lib_614")
        settings = sso_client.get_settings()
        self.assertEqual(
            settings.get("provider_discovery_uri"), "http://uvw/xyz/realms/abc"
        )

    @override_settings(
        DJANGO_PYOIDC={
            "lib_885": {
                "OIDC_CACHE_PROVIDER_METADATA": False,
                "CLIENT_ID": "foo2",
                "CLIENT_SECRET": "secret_app_foo2",
                "CACHE_DJANGO_BACKEND": "default",
                "PROVIDER_DISCOVERY_URI": "http://localhost:8080/auth/realms/stuff",
                "OIDC_CALLBACK_PATH": "/callback-foo-def",
                "LOGIN_URIS_REDIRECT_ALLOWED_HOSTS": ["foo2", "bar2"],
                "LOGIN_REDIRECTION_REQUIRES_HTTPS": True,
                "POST_LOGIN_URI_SUCCESS": "/abc-123-2",
                "POST_LOGIN_URI_FAILURE": "/def-456-2",
                "POST_LOGOUT_REDIRECT_URI": "/ghj-789-2",
                "HOOK_USER_LOGIN": "tests.e2e.test_app.callback:login_callback",
                "HOOK_USER_LOGOUT": "tests.e2e.test_app.callback:logout_callback",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_extracted_from_django_pyoidc_settings_upper(
        self, mocked_provider_config, *args
    ):
        """
        Test that definitions of DJANGO_PYOIDC in settings can be retrieved in client settings.

        Here testing that cas is not taken into account.
        """
        sso_client = OIDCClient(op_name="lib_885")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("client_id"), "foo2")
        self.assertEqual(settings.get("client_secret"), "secret_app_foo2")
        self.assertEqual(
            settings.get("provider_discovery_uri"),
            "http://localhost:8080/auth/realms/stuff",
        )
        self.assertEqual(settings.get("cache_django_backend"), "default")
        self.assertEqual(settings.get("oidc_cache_provider_metadata"), False)
        self.assertEqual(settings.get("oidc_callback_path"), "/callback-foo-def")
        self.assertEqual(
            settings.get("login_uris_redirect_allowed_hosts"), ["foo2", "bar2"]
        )
        self.assertEqual(settings.get("login_redirection_requires_https"), True)
        self.assertEqual(settings.get("post_login_uri_success"), "/abc-123-2")
        self.assertEqual(settings.get("post_login_uri_failure"), "/def-456-2")
        self.assertEqual(settings.get("post_logout_redirect_uri"), "/ghj-789-2")
        self.assertEqual(
            settings.get("hook_user_login"),
            "tests.e2e.test_app.callback:login_callback",
        )
        self.assertEqual(
            settings.get("hook_user_logout"),
            "tests.e2e.test_app.callback:logout_callback",
        )

    @override_settings(
        DJANGO_PYOIDC={
            "lib_901": {
                "oidc_cache_provider_metadata": False,
                "client_id": "zorg",
                "client_secret": "--",
                "provider_discovery_uri": "http://foobar/zorg/.well-known/openid-configuration/",
            },
            "lib_902": {
                "oidc_cache_provider_metadata": False,
                "client_id": "zorg",
                "client_secret": "--",
                "provider_discovery_uri": "http://foobar/zorg2/.well-known/openid-configuration",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_well_known_part_removed_from_provider_path(
        self, mocked_provider_config, *args
    ):
        """
        Test giving .well-known/openid-configuration/ paths for provider config paths is supported.
        """
        sso_client = OIDCClient(op_name="lib_901")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("provider_discovery_uri"), "http://foobar/zorg")
        sso_client = OIDCClient(op_name="lib_902")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("provider_discovery_uri"), "http://foobar/zorg2")

    @override_settings(
        DJANGO_PYOIDC={
            "lib_865": {
                "oidc_cache_provider_metadata": False,
                "client_id": "eorg",
                "client_secret": "--",
                "provider_discovery_uri": "http://foo",
            },
        },
    )
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_settings_globals(self, mocked_provider_config, *args):
        """
        Test that some globale settings are defined.
        """
        sso_client = OIDCClient(op_name="lib_865")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("CACHE_DJANGO_BACKEND"), "default")
        self.assertEqual(settings.get("cache_django_backend"), "default")
        self.assertEqual(settings.get("OIDC_CACHE_PROVIDER_METADATA"), False)
        self.assertEqual(settings.get("oidc_cache_provider_metadata"), False)
        self.assertEqual(settings.get("OIDC_CACHE_PROVIDER_METADATA_TTL"), 120)
        self.assertEqual(settings.get("oidc_cache_provider_metadata_ttl"), 120)
        self.assertEqual(settings.get("USE_INTROSPECTION_ON_ACCESS_TOKENS"), False)
        self.assertEqual(settings.get("use_introspection_on_access_tokens"), False)

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_client_use_introspection_on_access_tokens_defaults_to_true_if_name_drf(
        self, *args
    ):
        """
        Test that some globale settings are defined.
        """
        sso_client = OIDCClient(op_name="drf")
        settings = sso_client.get_settings()
        self.assertEqual(settings.get("USE_INTROSPECTION_ON_ACCESS_TOKENS"), True)
        self.assertEqual(settings.get("use_introspection_on_access_tokens"), True)
