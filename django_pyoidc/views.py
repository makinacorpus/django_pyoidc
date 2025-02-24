import logging
from importlib import import_module
from typing import Any, Dict, Optional, TypeVar, Union

# import oic
from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, resolve_url
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from jwt import JWT
from jwt.exceptions import JWTDecodeError
from oic.utils.http_util import BadRequest

from django_pyoidc.client import OIDCClient
from django_pyoidc.engine import OIDCEngine
from django_pyoidc.exceptions import InvalidSIDException
from django_pyoidc.models import OIDCSession
from django_pyoidc.settings import OIDCSettings, OIDCSettingsFactory, OidcSettingValue
from django_pyoidc.utils import import_object

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

logger = logging.getLogger(__name__)

T = TypeVar("T")


class OIDCMixin:
    op_name: str = ""
    opsettings: OIDCSettings


class OIDCView(View, OIDCMixin):
    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)
            if key == "op_name":
                self.opsettings = OIDCSettingsFactory.get(self.op_name)
                self.allowed_hosts = self.get_setting(
                    "login_uris_redirect_allowed_hosts"
                )

    def setup(self, request: HttpRequest, *args: Any, **kwargs: Any) -> None:
        super().setup(request, *args, **kwargs)
        if self.op_name is None:
            raise Exception(
                "Please set 'op_name' when initializing with 'as_view()'\nFor example : OIDCView.as_view(op_name='example')"
            )  # FIXME

    def get_setting(
        self, name: str, default: Optional[T] = None
    ) -> Optional[Union[T, OidcSettingValue]]:
        return self.opsettings.get(name, default)

    def call_function(self, setting_func_name: str, *args: Any, **kwargs: Any) -> Any:
        function_path: Optional[str] = self.opsettings.get(setting_func_name)  # type: ignore[assignment] # we can assume that the configuration is right
        if function_path is not None:
            func = import_object(function_path, "")
            return func(*args, **kwargs)

    def call_user_login_callback_function(
        self, request: HttpRequest, user: AbstractUser
    ) -> Any:
        logger.debug("OIDC, Calling user hook on login")
        self.call_function("hook_user_login", request, user)

    def call_logout_function(
        self, user_request: HttpRequest, logout_request_args: Dict[str, Any]
    ) -> Any:
        """Function called right before local session removal and before final redirection to the SSO server.

        Parameters:
            user_request : current user request on Django
            logout_request_args : current arguments added to the SSO server logout link. The final list of arguments
              is made by pyoidc and will add the id_token_hint element

        Returns:
            dict: extra query string arguments to add to the SSO disconnection url
        """
        return self.call_function("hook_user_logout", user_request, logout_request_args)

    def get_next_url(
        self, request: HttpRequest, redirect_field_name: str
    ) -> Optional[str]:
        """
        Adapted from https://github.com/mozilla/mozilla-django-oidc/blob/71e4af8283a10aa51234de705d34cd298e927f97/mozilla_django_oidc/views.py#L132
        """
        next_url = request.GET.get(redirect_field_name)
        if next_url:
            is_safe = url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts=self.allowed_hosts,  # type: ignore[arg-type] # let's just assume that this settings is correctly set
                require_https=self.get_setting(  # type: ignore[arg-type] # We can reasonably assume that this setting is a bool
                    "login_redirection_requires_https", True
                ),
            )
            if is_safe:
                return request.build_absolute_uri(next_url)
        return None


class OIDCLoginView(OIDCView):
    """
    When receiving a GET request, this views redirects the user to the SSO identified by `op_name`.
    This view is named ``<op_name>-login`` if you used ``get_urlpatterns``.

    This view supports the *http query parameter* ``next`` (ie ``?next=http://...``) to specify which url the user should be redirected to on success.

    First, an OIDC redirection is made to the sso, with a callback (redirection) set to a local url defined by the setting:

    * :ref:`oidc_callback_path` local path to be redirected after authentication on the sso, to finalize the local auth.

    After this somewhat internal redirection where the local auth is validated and the session created, a final redirection
    will be made.
    The final redirection behaviour is configured with the following settings :

    * :ref:`login_redirection_requires_https` controls if non https URIs are accepted.
    * :ref:`login_uris_redirect_allowed_hosts` controls which hosts the user can be redirected to.
    * :ref:`post_login_uri_success` defines the redirection URI when no 'next' redirect uri were provided in the HTTP request.
    """

    http_method_names = ["get"]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:

        sid = request.session.get("oidc_sid")
        if sid:
            client = OIDCClient(self.op_name, session_id=sid)
        else:
            client = OIDCClient(self.op_name)

        client.consumer.consumer_config["authz_page"] = self.get_setting(
            "oidc_callback_path"
        )
        next_redirect_uri = self.get_next_url(request, "next")

        if not next_redirect_uri:
            next_redirect_uri = str(
                self.get_setting(
                    "post_login_uri_success", request.build_absolute_uri("/")
                )
            )

        request.session["oidc_login_next"] = next_redirect_uri

        sid, location = client.consumer.begin(  # type: ignore[no-untyped-call] # oic package is untyped
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

    The response is a redirection to the SSO logout endpoint, if a provider configuration :ref:`post_logout_redirect_uri` exists it as used as
    post logout redirection argument on the SSO redirection link.

    """

    http_method_names = ["get", "post"]

    def post_logout_url(self, request: HttpRequest) -> str:
        """Return the post logout url defined in settings."""
        return str(
            self.get_setting(
                "post_logout_redirect_uri", request.build_absolute_uri("/")
            )
        )

    def get(self, request: HttpRequest) -> HttpResponse:
        return self.post(request)

    def post(self, request: HttpRequest) -> HttpResponse:
        """Log out the user."""
        url = self.post_logout_url(request)
        # If this url is not already an absolute url
        # we make it absolute using the current domain
        if not url[:7] in ["http://", "https:/"]:
            post_logout_url = request.build_absolute_uri(url)
        else:
            post_logout_url = url

        if not request.user.is_authenticated:
            redirect(post_logout_url)

        client = None
        sid = request.session.get("oidc_sid")

        redirect_arg_name: str = self.get_setting(
            "LOGOUT_QUERY_STRING_REDIRECT_PARAMETER",
            "post_logout_redirect_uri",
        )  # type: ignore[assignment] # we can assume that the configuration is right
        request_args = {
            redirect_arg_name: post_logout_url,
            "client_id": self.get_setting("client_id"),
        }

        # Allow some more parameters for some actors
        extra_logout_args: Dict[str, Any] = self.get_setting(  # type: ignore[assignment] # we can assume that the configuration is right
            "oidc_logout_query_string_extra_parameters_dict",
            {},
        )
        request_args.update(extra_logout_args)
        if sid:
            try:
                client = OIDCClient(self.op_name, session_id=sid)
            except (
                Exception
            ) as e:  # FIXME : Finer exception handling (KeyError,ParseError,CommunicationError)
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
                f"Cannot build the SSO disconnection link (maybe the cache was flushed ?), still redirecting directly to {post_logout_url}"
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

    def logout_sessions_by_sid(self, client: OIDCClient, sid: str, body: str) -> None:
        validated_sid = client.consumer.backchannel_logout(
            request_args={"logout_token": body}
        )
        if validated_sid != sid:
            raise InvalidSIDException(f"Got {validated_sid}, expected {sid}")
        sessions = OIDCSession.objects.filter(session_state=validated_sid)
        for session in sessions:
            self._logout_session(session)

    def logout_sessions_by_sub(self, client: OIDCClient, sub: str, body: str) -> None:
        sessions = OIDCSession.objects.filter(sub=sub)
        for session in sessions:
            client.consumer.backchannel_logout(request_args={"logout_token": body})
            self._logout_session(session)

    def _logout_session(self, session: OIDCSession) -> None:
        s = SessionStore()
        s.delete(session.cache_session_key)
        session.delete()
        logger.info(f"Backchannel logout request received and validated for {session}")

    def post(self, request: HttpRequest) -> HttpResponse:
        if request.content_type != "application/x-www-form-urlencoded":
            return HttpResponse("", status=415)
        result = HttpResponse("")
        try:
            body = request.body.decode("utf-8")[13:]
            decoded = JWT().decode(body, do_verify=False)  # type: ignore[no-untyped-call] # jwt.JWT is not typed yet

            sid = decoded.get("sid")
            sub = decoded.get("sub")
            if sub:
                # Authorization server wants to kill all sessions
                client = OIDCClient(self.op_name)
                self.logout_sessions_by_sub(client, sub, body)
            elif sid:
                client = OIDCClient(self.op_name, session_id=sid)
                try:
                    self.logout_sessions_by_sid(client, sid, body)
                except InvalidSIDException as e:
                    logger.debug(
                        f"Got invalid sid from request : expected {sid}. Error : \n{e}"
                    )
                    result.status_code = 400
            else:
                result.status_code = 400
                result.content = "Got invalid logout token : sub or sid is missing"
                logger.debug("Got invalid logout token : sub or sid is missing")
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

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.engine = OIDCEngine(self.opsettings)

    def success_url(self, request: HttpRequest) -> str:
        # Pull the next url from the session or settings --we don't need to
        # sanitize here because it should already have been sanitized.
        next_url = self.request.session.get("oidc_login_next", None)
        return next_url or resolve_url(
            self.get_setting("post_login_uri_success", request.build_absolute_uri("/"))  # type: ignore[arg-type] # we can assume that this setting is correctly configured
        )

    def login_failure(self, request: HttpRequest) -> HttpResponse:
        return redirect(
            str(
                self.get_setting(
                    "post_login_uri_failure", request.build_absolute_uri("/")
                )
            )
        )

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        try:
            if "oidc_sid" in request.session:
                self.client = OIDCClient(
                    self.op_name, session_id=request.session["oidc_sid"]
                )

                parsing_result = self.client.consumer.parse_authz(
                    query=request.GET.urlencode()
                )
                if isinstance(parsing_result, BadRequest):
                    logger.error(
                        "OIDC login process failure; cannot parse OIDC response"
                    )
                    return self.login_failure(request)

                aresp, atr, idt = parsing_result

                if aresp is None:
                    logger.error("OIDC login process failure; empty OIDC response")
                    return self.login_failure(request)

                if aresp["state"] == request.session["oidc_sid"]:
                    state = aresp["state"]
                    session_state = aresp.get("session_state")  # type: ignore[no-untyped-call] # oic is untyped yet

                    # pyoidc will make the next steps in OIDC login protocol
                    try:
                        tokens = self.client.consumer.complete(
                            state=state, session_state=session_state
                        )
                    except Exception as e:
                        logger.exception(e)
                        logger.error(
                            "OIDC login process failure; cannot end login protocol."
                        )
                        return self.login_failure(request)

                    # Collect data from userinfo endpoint
                    try:
                        userinfo = self.client.consumer.get_user_info(state=state)  # type: ignore[no-untyped-call] # oic is untyped yet
                    except Exception as e:
                        logger.exception(e)
                        logger.error(
                            "OIDC login process failure; Cannot retrieve userinfo."
                        )
                        return self.login_failure(request)

                    # TODO: add a setting to allow/disallow session storage of the tokens
                    access_token_jwt = (
                        tokens["access_token"] if "access_token" in tokens else None
                    )

                    # this will call token instrospection or user defined validator
                    # or return None
                    access_token_claims = self.engine.introspect_access_token(
                        access_token_jwt, self.client
                    )

                    id_token_claims = (
                        tokens["id_token"].to_dict() if "id_token" in tokens else None
                    )
                    # id_token_jwt = (
                    #     tokens["id_token_jwt"] if "id_token_jwt" in tokens else None
                    # )
                    userinfo_claims = userinfo.to_dict()
                    tokens = {
                        "info_token_claims": userinfo_claims,
                        "access_token_jwt": access_token_jwt,
                        "access_token_claims": access_token_claims,
                        "id_token_claims": id_token_claims,
                    }
                    # simplify check code, if any dict is None remove the entry
                    filtered_tokens = {k: v for k, v in tokens.items() if v is not None}
                    # Call user hook
                    user = self.engine.call_get_user_function(
                        tokens=filtered_tokens,
                        client=self.client,
                    )

                    if not user or not user.is_authenticated:
                        logger.error(
                            "OIDC login process failure. Cannot set active authenticated user."
                        )
                        return self.login_failure(request)
                    else:
                        auth.login(request, user)
                        OIDCSession.objects.create(
                            state=state,
                            sub=userinfo["sub"],
                            cache_session_key=request.session.session_key,  # type: ignore[misc] # we call auth.login right before, so session_key is set to a value
                            session_state=session_state,
                        )
                        self.call_user_login_callback_function(request, user)
                        redir = self.success_url(request)
                        return redirect(redir)
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
                return self.login_failure(request)
        except PermissionDenied as exc:
            logger.exception(exc)
            messages.error(request, "Permission Denied.")
            return self.login_failure(request)
