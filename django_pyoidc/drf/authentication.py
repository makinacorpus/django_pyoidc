import logging

from django.conf import settings
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from django_pyoidc.client import OIDCClient
from django_pyoidc.engine import OIDCEngine
from django_pyoidc.utils import OIDCCacheBackendForDjango, get_setting_for_sso_op

logger = logging.getLogger(__name__)


class OIDCBearerAuthentication(BaseAuthentication):
    def __init__(self, *args, **kwargs):
        super(OIDCBearerAuthentication, self).__init__(*args, **kwargs)
        self.op_name = self.extract_drf_opname()
        self.general_cache_backend = OIDCCacheBackendForDjango(self.op_name)
        self.client = OIDCClient(self.op_name)
        self.engine = OIDCEngine(self.op_name)

    def extract_drf_opname(self):
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
            msg = "Request missing the authorization header, invalid Keyword."
            raise exceptions.AuthenticationFailed(msg)
        val = val.strip()
        bearer_name, access_token_jwt = val.split(maxsplit=1)
        requested_bearer_name = get_setting_for_sso_op(
            self.op_name, "OIDC_API_BEARER_NAME", "Bearer"
        )
        if not bearer_name.lower() == requested_bearer_name.lower():
            msg = "Request missing the authorization header, invalid Keyword."
            raise exceptions.AuthenticationFailed(msg)
        return access_token_jwt

    def authenticate(self, request):
        """
        Returns two-tuple of (user, token) if authentication succeeds,
        or None otherwise.
        """
        try:
            user = None

            # Extract the access token from an HTTP Authorization Bearer header
            access_token_jwt = self.extract_access_token(request)
            # This introspection of the token is made by the SSO server
            # so it is quite slow, but there's a cache added based on the token expiration
            access_token_claims = self.engine.introspect_access_token(
                access_token_jwt, client=self.client
            )
            logger.error(access_token_claims)
            if not access_token_claims.get("active"):
                msg = "Inactive access token."
                raise exceptions.AuthenticationFailed(msg)
            # FIXME: audience check here

            # FIXME: add an option to request userinfo here, but that may be quite slow

            if access_token_claims:
                logger.info("Request has valid access token.")
                logger.debug("Let application load user via user hook.")
                user = self.engine.call_get_user_function(
                    tokens={
                        "access_token_jwt": access_token_jwt,
                        "access_token_claims": access_token_claims,
                    }
                )

            if not user or not user.is_authenticated:
                logger.error(
                    "OIDC Bearer Authentication process failure. Cannot set active authenticated user."
                )
                return None

        except Exception as exp:
            logger.exception(exp)
            return None

        return (user, None)
