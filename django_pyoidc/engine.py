import datetime
import logging
from typing import Any, Dict, MutableMapping, Optional, Union

from django_pyoidc import get_user_by_email
from django_pyoidc.client import OIDCClient
from django_pyoidc.exceptions import ExpiredToken, TokenError
from django_pyoidc.settings import OIDCSettings
from django_pyoidc.utils import OIDCCacheBackendForDjango, import_object

logger = logging.getLogger(__name__)


class OIDCEngine:
    def __init__(self, opsettings: OIDCSettings):
        self.opsettings = opsettings
        self.general_cache_backend = OIDCCacheBackendForDjango(opsettings)

    def call_function(self, setting_func_name: str, *args: Any, **kwargs: Any) -> Any:
        function_path: Optional[str] = self.opsettings.get(setting_func_name)  # type: ignore[assignment] # we can assume that the configuration is right
        if function_path is not None:
            func = import_object(function_path, "")
            return func(*args, **kwargs)

    def call_get_user_function(
        self, client: OIDCClient, tokens: Optional[Dict[str, Any]] = None
    ) -> Any:
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
    ) -> Any:
        """
        Perform a cached introspection call to extract claims from encoded jwt of the access_token
        """
        # FIXME: allow a non-cached mode by global settings

        if access_token_jwt is None:
            raise TokenError("Nothing in access_token_jwt.")

        if self.opsettings.get("use_introspection_on_access_tokens"):
            return self._call_introspection(access_token_jwt, client)
        else:
            return self.call_validate_tokens_hook(access_token_jwt, client)

    def _call_introspection(
        self, access_token_jwt: str, client: OIDCClient
    ) -> MutableMapping[str, Union[str, bool]]:
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
            )  # type: ignore[no-untyped-call] # oic is untyped
            introspection = client.client_extension.do_token_introspection(
                request_args=request_args,
                authn_method=client_auth_method,
                endpoint=client.consumer.introspection_endpoint,  # type: ignore
            )
            access_token_claims = introspection.to_dict()
            if "active" in access_token_claims and not access_token_claims["active"]:
                # there will not be other claims, like expiry, this is simply an expired token
                logger.info("access token introspection failed, expired token.")
                raise ExpiredToken("Inactive access token.")
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

    def call_validate_tokens_hook(
        self, access_token_jwt: str, client: OIDCClient
    ) -> Any:
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
