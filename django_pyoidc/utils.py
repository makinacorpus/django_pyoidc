import hashlib
import logging
from typing import Dict, Union

from django.conf import settings
from django.core.cache import BaseCache, caches

logger = logging.getLogger(__name__)


def get_setting_for_sso_op(op_name: str, key: str, default=None):
    if key in settings.DJANGO_PYOIDC[op_name]:
        return settings.DJANGO_PYOIDC[op_name][key]
    else:
        return default


def get_settings_for_sso_op(op_name: str):
    return settings.DJANGO_PYOIDC[op_name]


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
