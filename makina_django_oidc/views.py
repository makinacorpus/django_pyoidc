from django.shortcuts import redirect
from django.views import View
from oic import rndstr
from oic.oic import AuthorizationResponse, Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from makina_django_oidc.utils import get_settings_for_sso_op


class OIDCClient:
    def __init__(self, op_name):

        self.AUTH_ENDPOINT = get_settings_for_sso_op(op_name)["AUTHORIZATION_ENDPOINT"]
        self.REDIRECT_URI = get_settings_for_sso_op(op_name)["REDIRECT_URI"]

        self.client = Client(
            client_id=get_settings_for_sso_op(op_name)["CLIENT_ID"],
            client_authn_method=CLIENT_AUTHN_METHOD,
        )


class OIDCLoginView(View, OIDCClient):
    def get(self, request):

        state = rndstr()
        nonce = rndstr()
        request.session["nonce"] = nonce
        request.session["state"] = state

        args = {
            "client_id": self.client.client_id,
            "response_type": "code",
            "scope": ["openid"],
            "nonce": nonce,
            "redirect_uri": self.REDIRECT_URI,
            "state": state,
        }

        client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        auth_req = client.construct_AuthorizationRequest(request_args=args)
        return redirect(auth_req)


class OIDCCallbackView(View, OIDCClient):
    def get(self, request):
        aresp = self.client.parse_response(
            AuthorizationResponse, info=request.GET.urlencode(), sformat="urlencoded"
        )
        # code = aresp["code"]
        if aresp["state"] == request.session["state"]:
            args = {"code": aresp["code"]}

            resp = self.client.do_access_token_request(
                state=aresp["state"],
                request_args=args,
                authn_method="client_secret_basic",
            )
            print(f"OK : {resp}")
        else:
            print("FAIL")
