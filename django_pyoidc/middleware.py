import logging
from typing import Callable

from django.contrib import auth
from django.db import transaction
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone

from django_pyoidc.exceptions import DjangoOIDCException
from django_pyoidc.helper import OIDCHelper
from django_pyoidc.models import OIDCSession

logger = logging.getLogger(__name__)


class OIDCSessionExpirationMiddleware:
    """
    This is a middleware class managing OIDC session expiration.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """
        Code to be executed for each request before the view (and later middleware) are called.
        """
        if (
            request.user.is_authenticated
            and request.session.session_key
            and "oidc_sid" in request.session
            and "oidc_sid_valid" in request.session
            and request.session["oidc_sid"] == request.session["oidc_sid_valid"]
        ):
            # Note: base middleware chaining is done inside this function if the tests
            # are sucessful.
            return self._check_validity(request)
        else:
            # Base middleware chaining
            response = self.get_response(request)
            return response

    def _check_validity(self, request: HttpRequest) -> HttpResponse:
        """
        Check that the current OIDC session is not yet expired.

        Else we'll may have to expand it (refresh tokens) or terminate the django session.
        Termination will be a redirect response (for get requests) or a 401 HTTP error response.
        """
        # We select the current session expiration time from our
        # OIDC sessions table.
        # We use "select for update" to perform a read lock on this record,
        # this handles parallel requests from the same users where a slow
        # refresh token http action would have to occur in parallel and makes it
        # run only once.
        # But of course it also means that parallel requests from the same user
        # are locked here, so the lock must be released as soon as possible
        # as usually no specific refresh operation is needed. This is why we add a local
        # transaction around this select for update and the following actions.
        with transaction.atomic():
            try:
                oidc_session = OIDCSession.objects.select_for_update().get(
                    cache_session_key=request.session.session_key
                )
            # could happen once we provide multi-provider login on the same Dajngo session
            # which is not available currently, so that would be an error.
            except OIDCSession.MultipleObjectsReturned as e:
                message = "Middleware found several OIDC sessions with the same session_key."
                raise DjangoOIDCException(message) from e
            # Probable error case: OIDCSession was emptied but a session is still referencing an old id
            # the session is still referencing an sid but we do not have any info.
            except OIDCSession.DoesNotExist as e:
                # FIXME: maybe we could do something smarter. Like trating that has an invalidity case
                # but where we are sure we cannot try refresh tokens or any op related thing, as we
                # have no infos on the op
                message = "Middleware Cannot fetch OIDC session referenced in the django session from the cache."
                raise DjangoOIDCException(message) from e
            expiration = oidc_session.expiration
            op_name = oidc_session.op_name
            now = timezone.now()

            if now > expiration:
                # We are in a case where the expiration stored on the OIDC session, based on
                # the OIDC short-lifetime tokens, has been reached. That's 'normal' because
                # we store an expiration based on the relatively short 'exp' attributes of OIDC tokens.
                # The long term SSO session of the user (managed by the SSO server) may still be valid.
                # But it may also not be (disonnection from another SSO client not properly chained via
                # [back/front]channel logouts, so we are not aware that this session is not valid anymore).
                # We can do several things here:
                # - nothing: then the django local session will live its life until
                #   the default django session reachs its end. As if you did not add this middleware.
                # - logout the user and send an error page: but that would be bad, we do not even know
                #   if the user is requesting a page or action requiring auth.
                # - logout the user from django and redirect this user to the oidc login view, which
                #   may chain redirections automatically and validate a new lifetime for the oidc session.
                #   This is may be OK with GET/HEAD requests only.
                #   With non-get requests sending a redirection  is not the right way, an error code is better.
                #   We do not know if the POST was requiring auth but we know for sure it was a POST with
                #   an now invalid session, so an error code is valid (the user will have to redo it as anonymous).
                # - TODO: use oidc refresh tokens: then receive new tokens. That's the classical OIDC behavior,
                #   transparent for the user. In case of error in the refresh process we are back at previous point
                # Django disconnection
                auth.logout(request)
                # Note: no OIDC disconnection, the user session is maybe still valid on the
                # server and we DO NOT want to kill this OIDC session.
                # we send him back as an anonymous user
                if request.method in ["GET", "HEAD"]:
                    from pprint import pprint

                    try:
                        helper = OIDCHelper(op_name=op_name)
                        login_url = reverse(helper.login_uri_name)
                        return HttpResponseRedirect(login_url)
                    except Exception:
                        return HttpResponseRedirect("/")
                else:
                    return HttpResponse("Unauthorized", status=401)

        # Base middleware chaining
        response = self.get_response(request)
        return response
