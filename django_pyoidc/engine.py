import datetime
import logging

from django_pyoidc import get_user_by_email
from django_pyoidc.client import OIDCClient
from django_pyoidc.settings import OIDCSettings
from django_pyoidc.utils import OIDCCacheBackendForDjango, import_object

logger = logging.getLogger(__name__)


class OIDCEngine:
    def __init__(self, opsettings: OIDCSettings):
        self.opsettings = opsettings
        self.general_cache_backend = OIDCCacheBackendForDjango(opsettings)

    def call_function(self, setting_func_name, *args, **kwargs):
        function_path = self.opsettings.get(setting_func_name)
        if function_path:
            func = import_object(function_path, "")
            return func(*args, **kwargs)

    def call_get_user_function(self, tokens={}):
        if self.opsettings.get("HOOK_GET_USER"):
            logger.debug("OIDC, Calling user hook on get_user")
            return self.call_function("HOOK_GET_USER", tokens)
        else:
            return get_user_by_email(tokens)

    def introspect_access_token(self, access_token_jwt: str, client: OIDCClient):
        """
        Perform a cached introspection call to extract claims from encoded jwt of the access_token
        """
        # FIXME: allow a non-cached mode by global settings
        access_token_claims = None

        # FIXME: in what case could we do not have an access token available?
        # should we raise an error then?
        if access_token_jwt is not None:
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
