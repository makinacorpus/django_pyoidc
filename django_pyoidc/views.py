import logging
from importlib import import_module
from urllib.parse import urljoin

# import oic
from django.conf import settings
from django.contrib import auth
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse
from django.shortcuts import redirect, resolve_url
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from jwt import JWT
from jwt.exceptions import JWTDecodeError
from oic.oic.consumer import Consumer
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from django_pyoidc import get_user_by_email
from django_pyoidc.models import OIDCSession
from django_pyoidc.session import OIDCCacheSessionBackendForDjango
from django_pyoidc.utils import get_setting_for_sso_op, get_settings_for_sso_op

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

logger = logging.getLogger(__name__)


class InvalidSIDException(Exception):
    pass


def _import_object(path, def_name):
    try:
        mod, cls = path.split(":", 1)
    except ValueError:
        mod = path
        cls = def_name

    return getattr(import_module(mod), cls)


class OIDClient:
    def __init__(self, op_name, session_id=None):
        self._op_name = op_name

        self.cache_backend = OIDCCacheSessionBackendForDjango(self._op_name)

        consumer_config = {
            # "debug": True,
            "response_type": "code"
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

        base = get_settings_for_sso_op(op_name)["URI_PROVIDER"]
        path = get_settings_for_sso_op(op_name)["URI_CONFIG"]
        # avoid urljoin strange behaviors
        # like :
        #   http://localhost:8080/foo + /bar => http://localhost:8080/bar
        #   http://localhost:8080/foo/ + /bar => http://localhost:8080/bar
        # but
        #   http://localhost:8080/foo/ + bar => http://localhost:8080/foo/bar
        if not base.endswith("/"):
            base = f"{base}/"
        if path.startswith("/"):
            path = path[1:]
        provider_info_uri = urljoin(base, path)

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

    def call_function(self, setting_name, *args, **kwargs):
        function_path = get_settings_for_sso_op(self.op_name).get(setting_name)
        if function_path:
            func = _import_object(function_path, "")
            return func(*args, **kwargs)

    def call_get_user_function(self, info_token, access_token):
        user_function_setting_name = "USER_FUNCTION"
        if user_function_setting_name in get_settings_for_sso_op(self.op_name):
            return self.call_function(
                user_function_setting_name, info_token, access_token
            )
        else:
            return get_user_by_email(info_token, access_token)

    def call_callback_function(self, request, user):
        self.call_function("LOGIN_FUNCTION", request, user)

    def call_logout_function(self, user_request, logout_request_args):
        """Function called right before local session removal and before final redirection to the SSO server.

        Parameters:
            user_request : current user request on Django
            logout_request_args : current arguments added to the SSO server logout link. The final list of arguments
              is made by pyoidc and will add the id_token_hint element

        Returns:
            dict: extra query string arguments to add to the SSO disconnection url
        """
        return self.call_function("LOGOUT_FUNCTION", user_request, logout_request_args)

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
    """
    When receiving a GET request, this views redirects the user to the SSO identified by `op_name`.
    This view is named ``<op_name>-login`` if you used ``get_urlpatterns``.


    This view supports the *http query parameter* ``next`` (ie ``?next=http://...``) to specify which url the user should be redirected to on success.

    The redirection behaviour is configured with the following settings :

    * :ref:`REDIRECT_REQUIRES_HTTPS` controls if non https URIs are accepted.
    * :ref:`REDIRECT_ALLOWED_HOSTS` controls if which hosts the user can be redirected to.
    * :ref:`URI_DEFAULT_SUCCESS` defines the redirection URI when no 'next' redirect uri were provided in the HTTP request.
    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)

        client = OIDClient(self.op_name)
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
    """
    This view logs out the user, killing it's session on this service and notifying the identity provider that it has logged-out.
    It is named ``<op_name>-logout`` if you used ``get_urlpatterns``.

    It supports both ``GET`` and ``POST`` http methods.

    The response is a redirection to the SSO logout endpoint, if a provider configuration :ref:`URI_LOGOUT` exists it as used as
    post logout redirection argument on the SSO redirection link.

    """

    http_method_names = ["get", "post"]

    @property
    def post_logout_url(self):
        """Return the post logout url defined in settings."""
        return self.get_settings("URI_LOGOUT")

    def get(self, request):
        return self.post(request)

    def post(self, request):
        """Log out the user."""
        post_logout_url = self.post_logout_url

        if not request.user.is_authenticated:
            redirect(post_logout_url)

        client = None
        sid = request.session.get("oidc_sid")

        redirect_arg_name = get_setting_for_sso_op(
            self.op_name,
            "LOGOUT_QUERY_STRING_REDIRECT_PARAMETER",
            "post_logout_redirect_uri",
        )
        request_args = {
            redirect_arg_name: post_logout_url,
            "client_id": get_settings_for_sso_op(self.op_name)["CLIENT_ID"],
        }

        if sid:
            try:
                client = OIDClient(self.op_name, session_id=sid)
            except Exception as e:  # FIXME : Finer exception handling (KeyError,ParseError,CommunicationError)
                logger.error("OIDC Logout call error when loading OIDC state: ")
                logger.exception(e)

        # Hook user logout function
        extra_args = self.call_logout_function(request, request_args)
        if extra_args:
            extra_args.update(request_args)
        else:
            extra_args = request_args

        # Django disconnection
        auth.logout(request)

        if sid:
            OIDCSession.objects.filter(session_state=sid).delete()

        # Build SSO disconnect link
        if client:
            logout_request = client.consumer.message_factory.get_request_type(
                "endsession_endpoint"
            )
            url, body, http_args, _ = client.consumer.request_info(
                logout_request,
                method="GET",
                request_args=None,
                extra_args=extra_args,
                scope="",
                state=sid,
                prop="id_token_hint",
            )
            logger.debug("SSO logout: endsession redirect url: %s", url)
            return redirect(url)
        else:
            logger.error(
                f"Cannot build the SSO disconnection link, still redirecting directly to {post_logout_url}"
            )
            return redirect(post_logout_url)


@method_decorator(csrf_exempt, name="dispatch")
class OIDCBackChannelLogoutView(OIDCView):
    """
    This view only accept POST requests. This is where your identity provider notifies the library that we should kill a user
    session. Usually, you should not redirect a user manually to this view.

    It is named ``<op_name>-backchannel-logout`` if you used ``get_urlpatterns``.
    """

    http_method_names = ["post"]

    def logout_sessions_by_sid(self, client: OIDClient, sid: str, body):
        validated_sid = client.consumer.backchannel_logout(
            request_args={"logout_token": body}
        )
        if validated_sid != sid:
            raise InvalidSIDException(f"Got {validated_sid}, expected {sid}")
        sessions = OIDCSession.objects.filter(session_state=validated_sid)
        for session in sessions:
            self._logout_session(session)

    def logout_sessions_by_sub(self, client: OIDClient, sub: str, body):
        sessions = OIDCSession.objects.filter(sub=sub)
        for session in sessions:
            client.consumer.backchannel_logout(request_args={"logout_token": body})
            self._logout_session(session)

    def _logout_session(self, session: OIDCSession):
        s = SessionStore()
        s.delete(session.cache_session_key)
        session.delete()
        logger.info(f"Backchannel logout request received and validated for {session}")

    def post(self, request):
        if request.content_type != "application/x-www-form-urlencoded":
            return HttpResponse("", status=415)
        result = HttpResponse("")
        try:
            body = request.body.decode("utf-8")[13:]
            decoded = JWT().decode(body, do_verify=False)

            sid = decoded.get("sid")
            sub = decoded.get("sub")
            if sub:
                # Authorization server wants to kill all sessions
                client = OIDClient(self.op_name)
                self.logout_sessions_by_sub(client, sub, body)
            elif sid:
                client = OIDClient(self.op_name, session_id=sid)
                try:
                    self.logout_sessions_by_sid(client, sid, body)
                except InvalidSIDException as e:
                    logger.warning(
                        f"Got invalid sid from request : expected {sid}. Error : \n{e}"
                    )
                    result.status_code = 400
            else:
                result.status_code = 400
                result.content = "Got invalid logout token : sub or sid is missing"
                logger.warning("Got invalid logout token : sub or sid is missing")
        except JWTDecodeError:
            result.status_code = 400
        except UnicodeDecodeError as e:
            raise SuspiciousOperation(e)
        result.headers["Cache-Control"] = "no-store"
        return result


class OIDCCallbackView(OIDCView):
    """
    This view only accepts GET request. This is where the identity provider redirects the user in the *Authorization Code Flow*.
    Usually, you should not redirect a user manually to this view.

    It is named ``<op_name>-callback`` if you used ``get_urlpatterns``.
    """

    http_method_names = ["get"]

    @property
    def success_url(self):
        # Pull the next url from the session or settings --we don't need to
        # sanitize here because it should already have been sanitized.
        next_url = self.request.session.get("oidc_login_next", None)
        return next_url or resolve_url(self.get_settings("URI_DEFAULT_SUCCESS"))

    def login_failure(self):
        return redirect(self.get_settings("URI_FAILURE"))

    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)
        if "oidc_sid" in request.session:
            client = OIDClient(self.op_name, session_id=request.session["oidc_sid"])

            aresp, atr, idt = client.consumer.parse_authz(query=request.GET.urlencode())

            if aresp["state"] == request.session["oidc_sid"]:
                state = aresp["state"]
                session_state = aresp.get("session_state")

                # pyoidc will make the next steps in OIDC login protocol
                tokens = client.consumer.complete(
                    state=state, session_state=session_state
                )

                # Collect data from userinfo endpoint
                userinfo = client.consumer.get_user_info(state=state)

                # TODO: add a setting to allow/disallow session storage of the tokens
                # if "id_token_jwt" in tokens:
                #     request.session["oidc_id_token_jwt"] = tokens["id_token_jwt"]
                # if "access_token" in tokens:
                #     request.session["oidc_access_token"] = tokens["access_token"]
                # if "id_token" in tokens:
                #     request.session["oidc_id_token"] = tokens["id_token"].serialize()
                # request.session["oidc_userinfo"] = userinfo.serialize()

                # Call user hook
                # TODO: use id_token and not access_token has variable name
                logger.debug("OIDC, Calling user hook on get_user")
                user = self.call_get_user_function(
                    info_token=userinfo, access_token=tokens["id_token"]
                )

                if not user or not user.is_authenticated:
                    logger.warning(
                        "OIDC login process failure. Cannot set active authenticated user."
                    )
                    return self.login_failure()
                else:
                    auth.login(request, user)
                    OIDCSession.objects.create(
                        state=state,
                        sub=userinfo["sub"],
                        cache_session_key=request.session.session_key,
                        session_state=session_state,
                    )
                    self.call_callback_function(request, user)
                    return redirect(self.success_url)
            else:
                logger.warning(
                    "OIDC login process failure. OIDC state does not match session sid."
                )
                raise SuspiciousOperation(
                    "Login process: OIDC state does not match session sid."
                )
        else:
            logger.warning(
                "OIDC login process failure. No OIDC sid state in user session for a request on the OIDC callback."
            )
            return self.login_failure()