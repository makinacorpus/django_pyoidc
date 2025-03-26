from unittest import mock

from django.test import TestCase

from django_pyoidc.drf.schema import OIDCScheme


class OIDCShemaTestCase(TestCase):

    @mock.patch("django_pyoidc.drf.schema.OIDCSettingsFactory.get")
    def test_security_definition_no_well_known_endpoint(self, mocked_get_settings):
        mocked_get_settings.return_value = {
            "provider_discovery_uri": "https://sso.demo/realms/test"
        }
        result = OIDCScheme.get_security_definition(None)
        self.assertEqual(
            result["openIdConnectUrl"],
            "https://sso.demo/realms/test/.well-known/openid-configuration",
        )

    @mock.patch("django_pyoidc.drf.schema.OIDCSettingsFactory.get")
    def test_security_definition_with_well_known_endpoint(self, mocked_get_settings):
        mocked_get_settings.return_value = {
            "provider_discovery_uri": "https://sso.demo/realms/test/.well-known/openid-configuration"
        }
        result = OIDCScheme.get_security_definition(None)
        self.assertEqual(
            result["openIdConnectUrl"],
            "https://sso.demo/realms/test/.well-known/openid-configuration",
        )
