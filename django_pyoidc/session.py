import base64
import logging
from typing import Any, Dict, List, MutableMapping, Union

import jsonpickle  # type: ignore[import-untyped]
from Cryptodome.PublicKey.RSA import RsaKey, import_key
from django.core.cache import BaseCache, caches
from jsonpickle.handlers import BaseHandler  # type: ignore[import-untyped]
from oic.utils.session_backend import SessionBackend

from django_pyoidc.models import OIDCSession
from django_pyoidc.settings import OIDCSettings

logger = logging.getLogger(__name__)


# From https://github.com/alehuo/pyoidc-redis-session-backend/blob/master/pyoidc_redis_session_backend/__init__.py
class RSAKeyHandler(BaseHandler):  # type: ignore
    def flatten(
        self, obj: RsaKey, data: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        data["rsa_key"] = base64.b64encode(obj.export_key()).decode("utf-8")
        return data

    def restore(self, obj: Dict[str, str]) -> RsaKey:
        return import_key(base64.b64decode(obj["rsa_key"]))


jsonpickle.register(RsaKey, RSAKeyHandler)


class OIDCCacheSessionBackendForDjango(SessionBackend):
    """Implement Session backend using django cache."""

    def __init__(self, opsettings: OIDCSettings):
        cache_key: str = opsettings.get("cache_django_backend")  # type: ignore[assignment] # we can assume that the configuration is right
        self.storage: BaseCache = caches[cache_key]
        self.op_name = opsettings.get("op_name")

    def get_key(self, key: str) -> str:
        return f"{self.op_name}-{key}"

    def __setitem__(self, key: str, value: Dict[str, Union[str, bool]]) -> None:
        self.storage.set(self.get_key(key), jsonpickle.encode(value))

    def __getitem__(self, key: str) -> Dict[str, Union[str, bool]]:
        data = self.storage.get(self.get_key(key))
        if data is None:
            raise KeyError  # Makes __getItem__ handle like Python dict
        return jsonpickle.decode(data)

    def __delitem__(self, key: str) -> None:
        self.storage.delete(self.get_key(key))

    def __contains__(self, key: str) -> bool:
        return self.storage.get(self.get_key(key)) is not None

    def get_by_uid(self, uid: str) -> List[str]:
        # FIXME : maybe .filter(cache_session_key=uid) ?
        result = OIDCSession.objects.filter(cache_session_key=uid).values_list(
            "cache_session_key", flat=True
        )
        logger.debug(f"Fetched the following sid : {result} for {uid=}")

        return list(result)

    def get_by_sub(self, sub: str) -> List[str]:
        result = OIDCSession.objects.filter(sub=sub).values_list(
            "cache_session_key", flat=True
        )
        logger.debug(f"Fetched fhe following sid : {result} for {sub=}")
        return list(result)

    def get(self, attr: str, val: str) -> List[str]:
        logger.debug(f"Fetch SID for sessions where [{attr}] = {val}")
        raise NotImplementedError(
            "Current session implementation does not support this method"
        )
