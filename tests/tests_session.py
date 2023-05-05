from unittest import mock
from unittest.mock import ANY, call

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

        sso1.consumer._backup(sid="1234")
        sso2.consumer._backup(sid="1234")

        client_new = OIDClient(op_name="sso1", session_id="1234")

        mocked_provider_config.assert_has_calls([call(ANY), call(ANY)])
        self.assertEqual(client_new.consumer.client_id, "1")
