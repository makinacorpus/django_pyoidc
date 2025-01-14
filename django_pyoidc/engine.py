import datetime
import logging
from typing import Optional

from django_pyoidc import get_user_by_email
from django_pyoidc.client import OIDCClient
from django_pyoidc.exceptions import TokenError
from django_pyoidc.settings import OIDCSettings
from django_pyoidc.utils import OIDCCacheBackendForDjango, import_object

logger = logging.getLogger(__name__)


class OIDCEngine:
    def __init__(self, opsettings: OIDCSettings):
        self.opsettings = opsettings
        self.general_cache_backend = OIDCCacheBackendForDjango(opsettings)

    def call_function(self, setting_func_name, *args, **kwargs):
        function_path = self.opsettings.get(setting_func_name)
        if function_path is not None:
            func = import_object(function_path, "")
            return func(*args, **kwargs)

    def call_get_user_function(self, client: OIDCClient, tokens=None):
        if tokens is None:
            tokens = {}
        if self.opsettings.get("hook_get_user") is not None:
            logger.debug("OIDC, Calling user hook on get_user")
            return self.call_function("hook_get_user", client=client, tokens=tokens)
        else:
            logger.debug("OIDC, Calling get_user_by_email")
            return get_user_by_email(tokens)

    def introspect_access_token(
        self, access_token_jwt: Optional[str], client: OIDCClient
    ):
        """
        Perform a cached introspection call to extract claims from encoded jwt of the access_token
        """
        # FIXME: allow a non-cached mode by global settings

        if access_token_jwt is None:
            raise TokenError("Nothing in access_token_jwt.")

        if self.opsettings.get("use_introspection_on_access_tokens") is not None:
            return self._call_introspection(access_token_jwt, client)
        else:
            return self.call_validate_tokens_hook(access_token_jwt, client)

    def _call_introspection(self, access_token_jwt, client: OIDCClient):
        cache_key = self.general_cache_backend.generate_hashed_cache_key(
            access_token_jwt
        )
        try:
            access_token_claims = self.general_cache_backend[cache_key]
        except KeyError:
            # CACHE MISS

            # RFC 7662: token introspection: ask SSO to validate and render the jwt as json
            # this means a slow http call
            request_args = {
                "token": access_token_jwt,
                "token_type_hint": "access_token",
            }
            client_auth_method = client.consumer.registration_response.get(
                "introspection_endpoint_auth_method", "client_secret_basic"
            )
            introspection = client.client_extension.do_token_introspection(
                request_args=request_args,
                authn_method=client_auth_method,
                endpoint=client.consumer.introspection_endpoint,
            )
            access_token_claims = introspection.to_dict()

            # store it in cache
            current = datetime.datetime.now().strftime("%s")
            if "exp" not in access_token_claims:
                raise RuntimeError("No expiry set on the access token.")
            access_token_expiry = access_token_claims["exp"]
            exp = int(access_token_expiry) - int(current)
            logger.debug(
                f"Token expiry: {exp}  - current is {current} "
                f"and expiry is set to {access_token_expiry} in the token"
            )
            self.general_cache_backend.set(cache_key, access_token_claims, exp)
        return access_token_claims

    def call_validate_tokens_hook(self, access_token_jwt, client: OIDCClient):
        if self.opsettings.get("hook_validate_access_token") is not None:
            logger.debug("OIDC, Calling hook_validate_access_token.")
            return self.call_function(
                "hook_validate_access_token", access_token_jwt, client
            )
        else:
            logger.debug(
                "No way to extract claims from access token. 'use_introspection_on_access_tokens' is false and no user 'hook_validate_access_token' is defined. Empty dict return for access token."
            )
            return None
