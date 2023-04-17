import unittest
from unittest import TestCase
from unittest.mock import MagicMock, patch

from jwt import JWT
from oic.oic.consumer import Consumer
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.session_backend import DictSessionBackend


class Issue853TestCase(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Persistent session backend
        cls.session_backend = DictSessionBackend()

        # real JWT payload from a captured keycloak backchannel-logout request
        cls.body = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkRVl0UnRmVHpBbXpNZGxlWU5aSWhvQnI3bFNieHBQU3Z4N3Y1eWVCUlU4In0.eyJpYXQiOjE2ODAwOTA5NDUsImp0aSI6ImIzMGFjOTEyLWRhYjctNDkzZC04MGQxLTM2NWU0NmEwOWUyNyIsImlzcyI6Imh0dHA6Ly9rZXljbG9hay5sb2NhbDo4MDgwL2F1dGgvcmVhbG1zL0RlbW8iLCJhdWQiOiJmdWxsIiwic3ViIjoiYWJlYzcwZjgtYTJhMC00YmYwLTg2NjUtYWI5Mzg3YTRkZTAyIiwidHlwIjoiTG9nb3V0Iiwic2lkIjoiNDRlNTliOTYtYTVhMy00NWEwLWI0ZWYtNzY3NzdmNGI3YzI1IiwiZXZlbnRzIjp7Imh0dHA6Ly9zY2hlbWFzLm9wZW5pZC5uZXQvZXZlbnQvYmFja2NoYW5uZWwtbG9nb3V0Ijp7fX19.D4XFSfVp8_T4TwDWLvHx--rs9-aLS8ZbZNPMNWIanoil9gc3N8UczsHJqqTQVQU7BNDQKeMVZQn47I3A1gW9_5WhQa5Si5xgKUmBTs-BoUjLo9Avr7lqAc7zOcGD4ehVLX6gv3PxAlD04snqjEBBW2PZYOZ04u0E--Ssbqd_LAha7ArbgMDG8dIBmJUHvJNMhWERX3QKw5cc3TXcY1TbZ-xDdkBf28DJ19ryXMHn0PybH927ZsDGX-2vxltDFRbIhotPXfoAbfZl8_TA84tn58zKcWKNd5aMtZ5Mu0D_SHPcNNpbYR3WzMlQZ6E0_8io5_buUBehaKZTryL30rK56w"

    @unittest.skip("This is a test for : https://github.com/CZ-NIC/pyoidc/issues/853")
    def test_bug(self):

        consumer_config = {
            # "debug": True,
            "response_type": "code",
        }

        client_config = {
            "client_id": "test",
            "client_authn_method": CLIENT_AUTHN_METHOD,
        }

        consumer = Consumer(
            consumer_config=consumer_config,
            client_config=client_config,
            session_db=self.session_backend,
        )

        with patch("oic.oic.consumer.BackChannelLogoutRequest") as mock:
            # Load jwt as python dict
            decoded = {"logout_token": JWT().decode(self.body, do_verify=False)}

            # Simulate previously made login : our session id is 0000
            real_sid = "0000"
            self.session_backend.update(
                real_sid, "smid", decoded["logout_token"]["sid"]
            )
            self.session_backend.update(real_sid, "sub", decoded["logout_token"]["sub"])
            self.session_backend.update(
                real_sid, "issuer", decoded["logout_token"]["iss"]
            )

            # Mock 'BackChannelLogoutRequest' as we don't want to check signature and stuff
            mocked_logout_request = MagicMock()
            mocked_logout_request.__getitem__.side_effect = decoded.__getitem__
            mock.return_value = mocked_logout_request

            # Uncomment the following line to have the test pass :
            # consumer.sso_db = consumer.sdb

            sid = consumer.backchannel_logout(request_args={"logout_token": self.body})

            self.assertIsNotNone(sid)
            self.assertEqual(sid, real_sid)
