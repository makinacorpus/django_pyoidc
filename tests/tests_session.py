from unittest import mock
from unittest.mock import call

from oic.oauth2 import ASConfigurationResponse

from django_pyoidc.client import OIDCClient
from django_pyoidc.settings import OIDCSettingsFactory
from django_pyoidc.utils import OIDCCacheBackendForDjango
from tests.utils import OIDCTestCase


class SessionTestCase(OIDCTestCase):
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_session_isolation_between_providers(self, mocked_provider_config):
        """
        Test that different SSO providers using same SID do not conflict.
        """
        sso1 = OIDCClient(op_name="sso1")
        sso2 = OIDCClient(op_name="sso2")

        mocked_provider_config.assert_has_calls(
            [call("http://sso1/realms/realm1"), call("http://sso2/uri")]
        )
        assert 2 == mocked_provider_config.call_count

        sso1.consumer._backup(sid="1234")
        sso2.consumer._backup(sid="1234")

        # no more calls
        mocked_provider_config.assert_has_calls(
            [call("http://sso1/realms/realm1"), call("http://sso2/uri")]
        )
        assert 2 == mocked_provider_config.call_count

        client1 = OIDCClient(op_name="sso1", session_id="1234")
        self.assertEqual(client1.consumer.client_id, "1")

        client2 = OIDCClient(op_name="sso2", session_id="1234")

        # no more calls
        mocked_provider_config.assert_has_calls(
            [call("http://sso1/realms/realm1"), call("http://sso2/uri")]
        )
        assert 2 == mocked_provider_config.call_count

        self.assertEqual(client2.consumer.client_id, "2")

    @mock.patch(
        "django_pyoidc.client.Consumer.provider_config",
        return_value=ASConfigurationResponse(),
    )
    def test_session_isolation_between_providers_cached(self, mocked_provider_config):
        """
        Test that different SSO providers with active cache using same SID do not conflict
        """

        # empty the caches
        settings1 = OIDCSettingsFactory.get("sso3")
        settings2 = OIDCSettingsFactory.get("sso4")
        cache1 = OIDCCacheBackendForDjango(settings1)
        cache2 = OIDCCacheBackendForDjango(settings2)
        cache1.clear()
        cache2.clear()

        sso1 = OIDCClient(op_name="sso3")
        mocked_provider_config.assert_has_calls([call("http://sso3/uri")])
        assert 1 == mocked_provider_config.call_count

        sso2 = OIDCClient(op_name="sso4")
        mocked_provider_config.assert_has_calls(
            [call("http://sso3/uri"), call("http://sso4/uri")]
        )
        assert 2 == mocked_provider_config.call_count

        sso1.consumer._backup(sid="1234")
        sso2.consumer._backup(sid="1234")

        client1 = OIDCClient(op_name="sso3", session_id="1234")
        self.assertEqual(client1.consumer.client_id, "3")

        client2 = OIDCClient(op_name="sso4", session_id="1234")
        self.assertEqual(client2.consumer.client_id, "4")

        mocked_provider_config.assert_has_calls(
            [call("http://sso3/uri"), call("http://sso4/uri")]
        )
        assert 2 == mocked_provider_config.call_count
