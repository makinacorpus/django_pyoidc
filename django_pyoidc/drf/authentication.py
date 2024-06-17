import functools
import logging

from django.conf import settings
from django.core.exceptions import PermissionDenied
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from django_pyoidc.client import OIDCClient
from django_pyoidc.engine import OIDCEngine
from django_pyoidc.utils import (
    OIDCCacheBackendForDjango,
    check_audience,
    get_setting_for_sso_op,
)

logger = logging.getLogger(__name__)


class OidcAuthException(Exception):
    pass


class OIDCBearerAuthentication(BaseAuthentication):
    def __init__(self, *args, **kwargs):
        super(OIDCBearerAuthentication, self).__init__(*args, **kwargs)
        self.op_name = self.extract_drf_opname()
        self.general_cache_backend = OIDCCacheBackendForDjango(self.op_name)
        self.engine = OIDCEngine(self.op_name)

    @functools.cached_property
    def client(self):
        return OIDCClient(self.op_name)

    @classmethod
    def extract_drf_opname(cls):
        """
        Given a list of opnames and setting in DJANGO_PYOIDC conf, extract the one having USED_BY_REST_FRAMEWORK=True.
        """
        op = None
        found = False
        for op_name, configs in settings.DJANGO_PYOIDC.items():
            if (
                "USED_BY_REST_FRAMEWORK" in configs
                and configs["USED_BY_REST_FRAMEWORK"]
            ):
                if found:
                    raise RuntimeError(
                        "Several DJANGO_PYOIDC sections are declared as USED_BY_REST_FRAMEWORK, only one should be used."
                    )
                found = True
                op = op_name
        if found:
            return op
        else:
            raise RuntimeError(
                "No DJANGO_PYOIDC sections are declared with USED_BY_REST_FRAMEWORK configuration option."
            )

    def extract_access_token(self, request) -> str:
        val = request.headers.get("Authorization")
        if not val:
            msg = "Request missing the authorization header."
            raise OidcAuthException(msg)
        val = val.strip()
        bearer_name, access_token_jwt = val.split(maxsplit=1)
        requested_bearer_name = get_setting_for_sso_op(
            self.op_name, "OIDC_API_BEARER_NAME", "Bearer"
        )
        if not bearer_name.lower() == requested_bearer_name.lower():
            msg = f"Bad authorization header, invalid Keyword for the bearer, expecting {requested_bearer_name}."
            raise OidcAuthException(msg)
        return access_token_jwt

    def authenticate(self, request):
        """
        Returns two-tuple of (user, token) if authentication succeeds,
        or None otherwise.
        """
        try:
            user = None
            access_token_claims = None

            # Extract the access token from an HTTP Authorization Bearer header
            try:
                access_token_jwt = self.extract_access_token(request)
            except OidcAuthException as e:
                logger.debug(e)
                return None

            # This introspection of the token is made by the SSO server
            # so it is quite slow, but there's a cache added based on the token expiration
            access_token_claims = self.engine.introspect_access_token(
                access_token_jwt, client=self.client
            )
            logger.debug(access_token_claims)
            if not access_token_claims.get("active"):
                msg = "Inactive access token."
                raise exceptions.AuthenticationFailed(msg)

            # FIXME: add an option to request userinfo here, but that may be quite slow

            if access_token_claims:
                logger.debug("Request has valid access token.")

                # FIXME: Add a setting to disable
                client_id = get_setting_for_sso_op(self.op_name, "OIDC_CLIENT_ID")
                if not check_audience(client_id, access_token_claims):
                    raise PermissionDenied(
                        f"Invalid result for acces token audiences check for {client_id}."
                    )

                logger.debug("Let application load user via user hook.")
                user = self.engine.call_get_user_function(
                    tokens={
                        "access_token_jwt": access_token_jwt,
                        "access_token_claims": access_token_claims,
                    }
                )

            if not user:
                # OIDC Bearer Authentication process failure : cannot set active authenticated user
                return None

        except PermissionDenied as exp:
            raise exp
        except Exception as exp:
            logger.exception(exp)
            return None

        return user, access_token_claims
