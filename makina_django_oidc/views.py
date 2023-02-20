import pprint
from importlib import import_module
from urllib.parse import urljoin

from django.conf import settings
from django.contrib import auth, messages
from django.shortcuts import redirect, resolve_url
from django.utils.http import url_has_allowed_host_and_scheme
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

    def get_settings(self, name):
        return get_settings_for_sso_op(self.op_name)[name]

    def get_next_url(self, request, redirect_field_name):
        """Retrieves next url from request
        Note: This verifies that the url is safe before returning it. If the url
        is not safe, this returns None.
        :arg HttpRequest request: the http request
        :arg str redirect_field_name: the name of the field holding the next url
        :returns: safe url or None
        """
        next_url = request.GET.get(redirect_field_name)
        if next_url:

            is_safe = url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts=self.get_settings("REDIRECT_ALLOWED_HOSTS"),
                require_https=self.get_settings("REDIRECT_REQUIRES_HTTPS"),
            )
            if is_safe:
                return next_url
        return None


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

        request.session["oidc_login_next"] = self.get_next_url(request, "next")

        return redirect(redirect_uri)


class OIDCLogoutView(OIDCView):
    @property
    def redirect_url(self):
        """Return the logout url defined in settings."""
        return self.get_settings("REDIRECT_LOGOUT_URI")

    def get(self, request):
        return self.post(request)

    def post(self, request):
        """Log out the user."""
        logout_url = self.redirect_url
        #
        # client = OIDClient(self.op_name)
        # client.client.construct_EndSessionRequest()

        if request.user.is_authenticated:
            # Check if a method exists to build the URL to log out the user
            # from the OP.
            # logout_from_op = self.get_settings("OIDC_OP_LOGOUT_URL_METHOD", "")
            # if logout_from_op:
            #     logout_url = import_string(logout_from_op)(request)

            # Log out the Django user if they were logged in.
            auth.logout(request)

        return redirect(logout_url)


class OIDCCallbackView(OIDCView):
    @property
    def success_url(self):
        # Pull the next url from the session or settings--we don't need to
        # sanitize here because it should already have been sanitized.
        next_url = self.request.session.get("oidc_login_next", None)
        return next_url or resolve_url(
            self.get_settings("REDIRECT_SUCCESS_DEFAULT_URI")
        )

    def login_failure(self):
        return redirect(self.get_settings(["REDIRECT_FAILURE_URI"]))

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
                        return redirect(self.success_url)

        print("FAIL")
        messages.error(request, "Login failure")
        return self.login_failure()
