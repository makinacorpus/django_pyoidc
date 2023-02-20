import pprint
from importlib import import_module
from urllib.parse import urljoin

from django.conf import settings
from django.contrib import auth, messages
from django.shortcuts import redirect
from django.views import View
from oic import rndstr
from oic.oauth2 import AccessTokenResponse
from oic.oic import AuthorizationResponse, Client, OpenIDSchema
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from makina_django_oidc.utils import get_settings_for_sso_op

try:
    GET_USER_FUNCTION = settings.AUTH_GET_USER_FUNCTION
except AttributeError:
    GET_USER_FUNCTION = "makina_django_oidc:get_user_by_email"


def _import_object(path, def_name):
    try:
        mod, cls = path.split(":", 1)
    except ValueError:
        mod = path
        cls = def_name

    return getattr(import_module(mod), cls)


get_user = _import_object(GET_USER_FUNCTION, "get_user")


def get_oidc_client(op_name, client_id, provider_uri, redirect_uri):

    provider_info_uri = urljoin(
        provider_uri,
        get_settings_for_sso_op(op_name)["CONFIG_URI"],
    )
    op_info = Client(
        client_id=client_id,
        client_authn_method=CLIENT_AUTHN_METHOD,
    ).provider_config(provider_info_uri)

    client = Client(
        client_id=client_id,
        client_authn_method=CLIENT_AUTHN_METHOD,
    )

    client.handle_provider_config(op_info, op_info["issuer"])
    client.redirect_uris = [redirect_uri]
    client.client_secret = get_settings_for_sso_op(op_name)["CLIENT_SECRET"]
    return client


class OIDClient:
    def __init__(self, op_name):
        self._op_name = op_name
        self.client_id = get_settings_for_sso_op(op_name)["CLIENT_ID"]
        self.redirect_uri = get_settings_for_sso_op(op_name)["REDIRECT_URI"]
        self.provider_uri = get_settings_for_sso_op(op_name)["PROVIDER_URI"]
        self.client = get_oidc_client(
            self._op_name, self.client_id, self.provider_uri, self.redirect_uri
        )


class OIDCMixin:
    op_name = None


class OIDCView(View, OIDCMixin):
    def get(self, *args, **kwargs):
        if self.op_name is None:
            raise Exception(
                "Please set 'op_name' when initializing with 'as_view()'"
            )  # FIXME


class OIDCLoginView(OIDCView):
    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)
        client = OIDClient(self.op_name)
        state = rndstr()
        nonce = rndstr()
        request.session["nonce"] = nonce
        request.session["state"] = state

        args = {
            "client_id": client.client_id,
            "response_type": "code",
            "scope": ["openid"],
            "nonce": nonce,
            "redirect_uri": client.redirect_uri,
            "state": state,
        }
        auth_req = client.client.construct_AuthorizationRequest(request_args=args)
        redirect_uri = auth_req.request(client.client.authorization_endpoint)

        return redirect(redirect_uri)


class OIDCCallbackView(OIDCView):
    def login_failure(self):
        return redirect(get_settings_for_sso_op(self.op_name)["REDIRECT_FAILURE_URI"])

    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)

        client = OIDClient(self.op_name)

        aresp = client.client.parse_response(
            AuthorizationResponse, info=request.GET.urlencode(), sformat="urlencoded"
        )
        # code = aresp["code"]
        if aresp["state"] == request.session["state"]:
            args = {"code": aresp["code"]}

            resp = client.client.do_access_token_request(
                state=aresp["state"],
                request_args=args,
                authn_method="client_secret_basic",
            )
            print(f"OK : {resp}")

            if isinstance(resp, AccessTokenResponse):
                userinfo = client.client.do_user_info_request(state=aresp["state"])
                if isinstance(userinfo, OpenIDSchema):
                    print(f"{userinfo=}")
                    pprint.pprint(userinfo)
                    print("===================")
                    user = get_user(userinfo)
                    print(f"{user=}")

                    if not user or not user.is_authenticated:
                        messages.error(request, "Login failure")
                        return self.login_failure()
                    else:
                        auth.login(request, user)
                        messages.success(request, "Login successful")
                        return redirect("/")

        print("FAIL")
        messages.error(request, "Login failure")
        return self.login_failure()
