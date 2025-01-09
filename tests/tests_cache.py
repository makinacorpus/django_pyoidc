from unittest import mock
from unittest.mock import call

from oic.oauth2 import ASConfigurationResponse

from django_pyoidc.client import OIDCClient
from django_pyoidc.settings import OIDCSettingsFactory
from django_pyoidc.utils import OIDCCacheBackendForDjango
from tests.utils import OIDCTestCase


class CacheTestCase(OIDCTestCase):
    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_providers_info_not_cached(self, mocked_provider_config):
        """
        Test that multiple Clients creation without cache means several provider_info calls
        """
        # OIDCClient creation generates one call to Consumer.provider_config
        sso1 = OIDCClient(op_name="sso1")
        mocked_provider_config.assert_has_calls([call("http://sso1/realms/realm1")])
        assert 1 == mocked_provider_config.call_count

        # restoring a user session does not create a new call
        sso1.consumer._backup(sid="1234")
        OIDCClient(op_name="sso1", session_id="1234")
        mocked_provider_config.assert_has_calls([call("http://sso1/realms/realm1")])
        assert 1 == mocked_provider_config.call_count

        # but a new empty Client would add a new metadata call
        OIDCClient(op_name="sso1")
        mocked_provider_config.assert_has_calls(
            [call("http://sso1/realms/realm1"), call("http://sso1/realms/realm1")]
        )
        assert 2 == mocked_provider_config.call_count

    @mock.patch(
        "django_pyoidc.client.Consumer.provider_config",
        return_value=ASConfigurationResponse(),
    )
    def test_providers_info_cached(self, mocked_provider_config):
        """
        Test that multiple Clients creation with cache means only one provider_info call.
        """
        # empty the caches
        settings1 = OIDCSettingsFactory.get("sso3")
        settings2 = OIDCSettingsFactory.get("sso4")
        cache1 = OIDCCacheBackendForDjango(settings1)
        cache1.clear()
        cache2 = OIDCCacheBackendForDjango(settings2)
        cache2.clear()

        # OIDCClient creation generates one call to Consumer.provider_config
        sso1 = OIDCClient(op_name="sso3")
        mocked_provider_config.assert_has_calls([call("http://sso3/uri")])
        assert 1 == mocked_provider_config.call_count

        # restoring a user session does not create a new call
        sso1.consumer._backup(sid="1234")
        OIDCClient(op_name="sso3", session_id="1234")
        mocked_provider_config.assert_has_calls([call("http://sso3/uri")])
        assert 1 == mocked_provider_config.call_count

        # creating a new OIDCClient should activate shared cache
        # and prevent a new call
        OIDCClient(op_name="sso3")
        mocked_provider_config.assert_has_calls([call("http://sso3/uri")])
        assert 1 == mocked_provider_config.call_count

        # BUT adding a new Client with a different op_name will add a call,
        # as it is not the same cache key
        OIDCClient(op_name="sso4")

        mocked_provider_config.assert_has_calls(
            [call("http://sso3/uri"), call("http://sso4/uri")]
        )
        assert 2 == mocked_provider_config.call_count
