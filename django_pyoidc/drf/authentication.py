import functools
import logging
from typing import Any, Optional, Tuple

from django.core.exceptions import PermissionDenied
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request
from typing_extensions import override

from django_pyoidc.client import OIDCClient
from django_pyoidc.engine import OIDCEngine
from django_pyoidc.exceptions import ExpiredToken
from django_pyoidc.settings import OIDCSettingsFactory
from django_pyoidc.utils import OIDCCacheBackendForDjango, check_audience

logger = logging.getLogger(__name__)


class OidcAuthException(Exception):
    pass


class OIDCBearerAuthentication(BaseAuthentication):
    def __init__(self, *args: Any, **kwargs: Any):
        super(OIDCBearerAuthentication, self).__init__(*args, **kwargs)
        self.opsettings = OIDCSettingsFactory.get("drf")
        self.general_cache_backend = OIDCCacheBackendForDjango(self.opsettings)
        self.engine = OIDCEngine(self.opsettings)

    @functools.cached_property
    def client(self) -> OIDCClient:
        return OIDCClient("drf")

    def extract_access_token(self, request: Request) -> str:
        val = request.headers.get("Authorization")
        if not val:
            msg = "Request missing the authorization header."
            raise OidcAuthException(msg)
        val = val.strip()
        bearer_name, access_token_jwt = val.split(maxsplit=1)
        requested_bearer_name = self.opsettings.get("oidc_api_bearer_name", "Bearer")
        if not bearer_name.lower() == requested_bearer_name.lower():  # type: ignore[union-attr] # we can assume that this setting is a string
            msg = f"Bad authorization header, invalid Keyword for the bearer, expecting {requested_bearer_name} (check setting oidc_api_bearer_name)."
            raise OidcAuthException(msg)
        return access_token_jwt

    @override
    def authenticate(self, request: Request) -> Optional[Tuple[Any, Any]]:
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
            # it could also call a user defined validator if 'use_introspection_on_access_tokens'
            # is False. or it could return None if the two previous are not defined.
            try:
                access_token_claims = self.engine.introspect_access_token(
                    access_token_jwt, client=self.client
                )
            except ExpiredToken:
                msg = "Inactive access token."
                raise exceptions.AuthenticationFailed(msg)

            if not access_token_claims:
                exceptions.AuthenticationFailed(
                    "Access token claims failed to be extracted."
                )
            logger.debug(access_token_claims)
            if not access_token_claims.get("active"):
                msg = "Inactive access token."
                raise exceptions.AuthenticationFailed(msg)

            # FIXME: add an option to request userinfo here, but that may be quite slow

            if access_token_claims:
                logger.debug("Request has valid access token.")

                # FIXME: Add a setting to disable
                client_id: str = self.opsettings.get("client_id")  # type: ignore[assignment] # we can assume that client_id is correctly configured
                if not check_audience(client_id, access_token_claims):
                    raise PermissionDenied(
                        f"Invalid result for acces token audiences check for {client_id}."
                    )

                logger.debug("Let application load user via user hook.")
                user = self.engine.call_get_user_function(
                    tokens={
                        "access_token_jwt": access_token_jwt,
                        "access_token_claims": access_token_claims,
                    },
                    client=self.client,
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
