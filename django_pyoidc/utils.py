import hashlib
import logging
from importlib import import_module
from typing import Any, Dict, Union

from django.conf import settings
from django.core.cache import BaseCache, caches

from django_pyoidc.exceptions import ClaimNotFoundError

logger = logging.getLogger(__name__)


def get_setting_for_sso_op(op_name: str, key: str, default=None):
    if key in settings.DJANGO_PYOIDC[op_name]:
        return settings.DJANGO_PYOIDC[op_name][key]
    else:
        return default


def get_settings_for_sso_op(op_name: str):
    return settings.DJANGO_PYOIDC[op_name]


def import_object(path, def_name):
    try:
        mod, cls = path.split(":", 1)
    except ValueError:
        mod = path
        cls = def_name

    return getattr(import_module(mod), cls)


def extract_claim_from_tokens(claim: str, tokens: dict) -> Any:
    """Given a dictionnary of tokens claims, extract the given claim.

    This function will seek in "info_token_claims", then "id_token_claims"
    and finally "access_token_claims".
    If the claim is not found a ClaimNotFoundError exception is raised.
    """
    if "info_token_claims" in tokens and claim in tokens["info_token_claims"]:
        value = tokens["info_token_claims"][claim]
    elif "id_token_claims" in tokens and claim in tokens["id_token_claims"]:
        value = tokens["id_token_claims"][claim]
    elif "access_token_claims" and claim in tokens["access_token_claims"]:
        value = tokens["access_token_claims"][claim]
    else:
        raise ClaimNotFoundError(f"{claim} not found in available OIDC tokens.")
    return value


class OIDCCacheBackendForDjango:
    """Implement General cache for OIDC using django cache"""

    def __init__(self, op_name):
        self.op_name = op_name
        self.enabled = get_setting_for_sso_op(
            self.op_name, "OIDC_CACHE_PROVIDER_METADATA", False
        )
        if self.enabled:
            self.storage: BaseCache = caches[
                get_setting_for_sso_op(self.op_name, "CACHE_DJANGO_BACKEND")
            ]

    def generate_hashed_cache_key(self, value: str) -> str:
        h = hashlib.new("sha256")
        h.update(value.encode())
        cache_key = h.hexdigest()
        return cache_key

    def clear(self):
        return self.storage.clear()

    def get_key(self, key):
        return f"oidc-{self.op_name}-{key}"

    def set(self, key: str, value: Dict[str, Union[str, bool]], expiry: int) -> None:
        if self.enabled:
            self.storage.set(self.get_key(key), value, expiry)

    def __getitem__(self, key: str) -> Dict[str, Union[str, bool]]:
        if self.enabled:
            data = self.storage.get(self.get_key(key))
            if data is None:
                raise KeyError  # Makes __getItem__ handle like Python dict
            return data
        else:
            raise KeyError
