from unittest import mock
from unittest.mock import MagicMock

from django_pyoidc.client import OIDCClient
from django_pyoidc.engine import OIDCEngine
from django_pyoidc.exceptions import InvalidOIDCConfigurationException
from django_pyoidc.settings import OIDCSettings
from tests.utils import OIDCTestCase


class OIDCEngineTestCase(OIDCTestCase):

    @mock.patch("django_pyoidc.client.Consumer.provider_config")
    def test_handle_missing_introspection_endpoint(self, *args):
        op_name = "sso1"
        settings = OIDCSettings(op_name=op_name)
        engine = OIDCEngine(opsettings=settings)

        access_token = "test_token"
        client = OIDCClient(op_name=op_name)

        mocked_do_introspection = MagicMock()
        mocked_do_introspection.side_effect = AttributeError()

        client.client_extension.do_token_introspection = mocked_do_introspection
        client.consumer.introspection_endpoint = "test_endpoint"

        with self.assertRaises(
            InvalidOIDCConfigurationException,
            msg=f"No introspection endpoint found for provider '{op_name}'",
        ):

            engine._call_introspection(access_token_jwt=access_token, client=client)
