import http.client as http_client
import logging
from urllib.parse import parse_qs, urlparse

import requests
from django.urls import reverse

from tests.utils import OIDCE2ETestCase

# HTTP debug for requests
http_client.HTTPConnection.debuglevel = 1


class KeycloakTestCase(OIDCE2ETestCase):
    def test_login_page_redirects_to_keycloak_sso(self, *args):
        """
        Test that accessing login callback redirects to the SSO server.
        """
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

        client = requests

        print(f"Running Django on {self.live_server_url}")

        self.registerClient("app1", "secret_app1", self.live_server_url)
        self.registerUser("user1", "passwd1")
        login_url = reverse("test_login")
        response = client.get(
            f"{self.live_server_url}{login_url}", allow_redirects=False
        )
        # we should get something like http://localhost:8080/auth/realms/realm1/protocol/openid-connect/auth
        #   ?client_id=app1
        #   &nonce=YZA...24
        #   &redirect_uri=http%3A%2F%2Ftestserver%2Fcallback
        #   &response_type=code
        #   &scope=openid
        #   &state=fe874.....538e047a0
        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "http")
        self.assertEqual(parsed.netloc, "localhost:8080")
        self.assertEqual(
            parsed.path, "/auth/realms/realm1/protocol/openid-connect/auth"
        )
        self.assertEqual(qs["client_id"][0], "app1")
        self.assertEqual(qs["redirect_uri"][0], f"{self.live_server_url}/callback")
        self.assertEqual(qs["response_type"][0], "code")
        self.assertEqual(qs["scope"][0], "openid")
        self.assertTrue(qs["state"][0])
        self.assertTrue(qs["nonce"][0])
