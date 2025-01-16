import hashlib
import logging
from importlib import import_module
from typing import Any, Dict, Mapping, MutableMapping, Optional, Union

from django.core.cache import BaseCache, caches

from django_pyoidc.exceptions import ClaimNotFoundError
from django_pyoidc.settings import OIDCSettings

logger = logging.getLogger(__name__)


def import_object(
    path: str, def_name: str
) -> Any:  # FIXME : this function is hard to type correctly
    try:
        mod, cls = path.split(":", 1)
    except ValueError:
        mod = path
        cls = def_name

    return getattr(import_module(mod), cls)


def extract_claim_from_tokens(
    claim: str, tokens: Dict[str, Any], raise_exception: bool = True
) -> Any:
    """Given a dictionnary of tokens claims, extract the given claim.

    This function will seek in "info_token_claims", then "id_token_claims"
    and finally "access_token_claims".
    If the claim is not found a ClaimNotFoundError exception is raised.
    """
    if "info_token_claims" in tokens and claim in tokens["info_token_claims"]:
        value = tokens["info_token_claims"][claim]
    elif "id_token_claims" in tokens and claim in tokens["id_token_claims"]:
        value = tokens["id_token_claims"][claim]
    elif "access_token_claims" in tokens and claim in tokens["access_token_claims"]:
        value = tokens["access_token_claims"][claim]
    else:
        if raise_exception:
            raise ClaimNotFoundError(f"{claim} not found in available OIDC tokens.")
        else:
            return None
    return value


def check_audience(client_id: str, access_token_claims: Dict[str, Any]) -> bool:
    """Verify that the current client_id is present in 'aud' claim.

    Audences are stored in 'aud' claim.
    Audiences of an access token is a list of client_id where this token is allowed.
    When receiving an access token in 'API' bearer mode checking that your client_id
    is in the audience is a must.
    Access tokens received in 'full' mode, when this Django is the OIDC client
    managing the redirections to the SSO server may not always contain the client_id
    in 'aud'. This is the case for Keycloak for example, where the 'aud' would only
    contain 'others' client_id where this token can be used, and not the one generating it.
    Audience in userinfo and id tokens are different beasts.
    """
    if "aud" not in access_token_claims:
        return False
    if client_id not in access_token_claims["aud"]:
        logger.error(
            f"{client_id} not found in access_token_claims['aud']: {access_token_claims['aud']}"
        )
        return False
    return True


class OIDCCacheBackendForDjango:
    """Implement General cache for OIDC using django cache"""

    def __init__(self, opsettings: OIDCSettings):
        self.op_name = opsettings.get("op_name")

        self.enabled = opsettings.get("oidc_cache_provider_metadata", False)
        if self.enabled:
            cache_key: str = opsettings.get("cache_django_backend")  # type: ignore[assignment] # we can assume that the configuration is right
            self.storage: BaseCache = caches[cache_key]

    def generate_hashed_cache_key(self, value: str) -> str:
        h = hashlib.new("sha256")
        h.update(value.encode())
        cache_key = h.hexdigest()
        return cache_key

    def clear(self) -> Optional[int]:
        if self.enabled:
            self.storage.clear()
            return None
        else:
            return 0

    def get_key(self, key: str) -> str:
        return f"oidc-{self.op_name}-{key}"

    def set(self, key: str, value: Mapping[str, Union[str, bool]], expiry: int) -> None:
        if self.enabled:
            self.storage.set(self.get_key(key), value, expiry)

    def __getitem__(self, key: str) -> MutableMapping[str, Union[str, bool]]:
        if self.enabled:
            data = self.storage.get(self.get_key(key))
            if data is None:
                raise KeyError  # Makes __getItem__ handle like Python dict
            return data
        else:
            raise KeyError
