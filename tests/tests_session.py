from unittest import mock
from unittest.mock import call

from django_pyoidc.utils import OIDCCacheBackendForDjango
from django_pyoidc.views import OIDClient
from tests.utils import OIDCTestCase


class SessionTestCase(OIDCTestCase):
    @mock.patch("django_pyoidc.views.Consumer.provider_config")
    def test_session_isolation_between_providers(self, mocked_provider_config):
        """
        Test that different SSO providers using same SID do not conflict
        """
        sso1 = OIDClient(op_name="sso1")
        sso2 = OIDClient(op_name="sso2")

        mocked_provider_config.assert_has_calls([call(""), call("")])
        assert 2 == mocked_provider_config.call_count

        sso1.consumer._backup(sid="1234")
        sso2.consumer._backup(sid="1234")

        # no more calls
        mocked_provider_config.assert_has_calls([call(""), call("")])
        assert 2 == mocked_provider_config.call_count

        client1 = OIDClient(op_name="sso1", session_id="1234")
        self.assertEqual(client1.consumer.client_id, "1")

        client2 = OIDClient(op_name="sso2", session_id="1234")

        # no more calls
        mocked_provider_config.assert_has_calls([call(""), call("")])
        assert 2 == mocked_provider_config.call_count

        self.assertEqual(client2.consumer.client_id, "2")

    @mock.patch(
        "django_pyoidc.views.Consumer.provider_config",
        return_value=('[{"foo": "bar"}]'),
    )
    def test_session_isolation_between_providers_cached(self, mocked_provider_config):
        """
        Test that different SSO providers with active cache using same SID do not conflict
        """

        # empty the caches
        cache1 = OIDCCacheBackendForDjango("sso3")
        cache2 = OIDCCacheBackendForDjango("sso4")
        cache1.clear()
        cache2.clear()

        sso1 = OIDClient(op_name="sso3")
        mocked_provider_config.assert_has_calls([call("http://sso3/uri")])
        assert 1 == mocked_provider_config.call_count

        sso2 = OIDClient(op_name="sso4")
        mocked_provider_config.assert_has_calls(
            [call("http://sso3/uri"), call("http://sso4/uri")]
        )
        assert 2 == mocked_provider_config.call_count

        sso1.consumer._backup(sid="1234")
        sso2.consumer._backup(sid="1234")

        client1 = OIDClient(op_name="sso3", session_id="1234")
        self.assertEqual(client1.consumer.client_id, "3")

        client2 = OIDClient(op_name="sso4", session_id="1234")
        self.assertEqual(client2.consumer.client_id, "4")

        mocked_provider_config.assert_has_calls(
            [call("http://sso3/uri"), call("http://sso4/uri")]
        )
        assert 2 == mocked_provider_config.call_count
