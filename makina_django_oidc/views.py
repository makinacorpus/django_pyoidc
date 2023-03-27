from importlib import import_module
from urllib.parse import urljoin

import oic
from django.conf import settings
from django.contrib import auth, messages
from django.shortcuts import redirect, resolve_url
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from oic.oic.consumer import Consumer
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from makina_django_oidc.session import OIDCSessionBackendForDjango
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


class OIDClient:
    def __init__(self, op_name, session_id=None):
        self._op_name = op_name

        self.cache_backend = OIDCSessionBackendForDjango(self._op_name)

        consumer_config = {
            # "debug": True,
            "response_type": "code",
        }

        client_config = {
            "client_id": get_settings_for_sso_op(op_name)["CLIENT_ID"],
            "client_authn_method": CLIENT_AUTHN_METHOD,
        }

        self.consumer = Consumer(
            session_db=self.cache_backend,
            consumer_config=consumer_config,
            client_config=client_config,
        )

        provider_info_uri = urljoin(
            get_settings_for_sso_op(op_name)["URI_PROVIDER"],
            get_settings_for_sso_op(op_name)["URI_CONFIG"],
        )

        if session_id:
            self.consumer.restore(session_id)
        else:
            self.consumer.provider_config(provider_info_uri)
            self.consumer.client_secret = get_settings_for_sso_op(op_name)[
                "CLIENT_SECRET"
            ]


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
        """
        Adapted from https://github.com/mozilla/mozilla-django-oidc/blob/71e4af8283a10aa51234de705d34cd298e927f97/mozilla_django_oidc/views.py#L132
        """
        next_url = request.GET.get(redirect_field_name)
        if next_url:
            is_safe = url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts=self.get_settings("REDIRECT_ALLOWED_HOSTS"),
                require_https=self.get_settings("REDIRECT_REQUIRES_HTTPS"),
            )
            if is_safe:
                return request.build_absolute_uri(next_url)
        return None


class OIDCLoginView(OIDCView):
    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)

        client = OIDClient(
            self.op_name,
        )
        client.consumer.consumer_config["authz_page"] = self.get_settings(
            "CALLBACK_PATH"
        )
        redirect_uri = self.get_next_url(request, "next")

        if not redirect_uri:
            redirect_uri = self.get_settings("URI_DEFAULT_SUCCESS")

        request.session["oidc_login_next"] = redirect_uri

        sid, location = client.consumer.begin(
            scope=["openid"],
            response_type="code",
            use_nonce=True,
            path=self.request.build_absolute_uri("/"),
        )

        request.session["oidc_sid"] = sid

        return redirect(location)


class OIDCLogoutView(OIDCView):
    @property
    def redirect_url(self):
        """Return the logout url defined in settings."""
        return self.get_settings("URI_LOGOUT")

    def get(self, request):
        return self.post(request)

    def post(self, request):
        """Log out the user."""
        logout_url = self.redirect_url

        if request.user.is_authenticated:
            client = OIDClient(self.op_name, session_id=request.session["oidc_sid"])

            try:
                client.consumer.do_end_session_request(
                    scope=["openid"], state=request.session["oidc_sid"]
                )
            except oic.oauth2.exception.ResponseError:
                pass  # FIXME : Keycloak error parsing => we shall create an issue
            auth.logout(request)

        return redirect(logout_url)


class OIDCCallbackView(OIDCView):
    @property
    def success_url(self):
        # Pull the next url from the session or settings--we don't need to
        # sanitize here because it should already have been sanitized.
        next_url = self.request.session.get("oidc_login_next", None)
        return next_url or resolve_url(self.get_settings("URI_DEFAULT_SUCCESS"))

    def login_failure(self):
        return redirect(self.get_settings(["URI_FAILURE"]))

    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)
        client = OIDClient(self.op_name, session_id=request.session["oidc_sid"])

        aresp, atr, idt = client.consumer.parse_authz(query=request.GET.urlencode())

        if aresp["state"] == request.session["oidc_sid"]:
            client.consumer.complete(state=aresp["state"])
            userinfo = client.consumer.get_user_info(state=aresp["state"])

            user = get_user(userinfo)  # Call user hook

            if not user or not user.is_authenticated:
                messages.error(request, "Login failure")
                return self.login_failure()
            else:
                auth.login(request, user)
                messages.success(request, "Login successful")
                return redirect(self.success_url)
        else:
            messages.error(request, "Login failure : suspicious operation")
            return self.login_failure()
