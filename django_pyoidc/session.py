import base64
import logging
from typing import Dict, List, Union

import jsonpickle
from Cryptodome.PublicKey.RSA import RsaKey, import_key
from django.core.cache import BaseCache, caches
from jsonpickle.handlers import BaseHandler
from oic.utils.session_backend import SessionBackend

from django_pyoidc.models import OIDCSession
from django_pyoidc.utils import get_settings_for_sso_op

logger = logging.getLogger(__name__)


# From https://github.com/alehuo/pyoidc-redis-session-backend/blob/master/pyoidc_redis_session_backend/__init__.py
class RSAKeyHandler(BaseHandler):
    def flatten(self, obj: RsaKey, data):
        data["rsa_key"] = base64.b64encode(obj.export_key()).decode("utf-8")
        return data

    def restore(self, obj):
        return import_key(base64.b64decode(obj["rsa_key"]))


jsonpickle.register(RsaKey, RSAKeyHandler)


class OIDCCacheSessionBackendForDjango(SessionBackend):
    """Implement Session backend using django cache"""

    def __init__(self, op_name):
        self.storage: BaseCache = caches[
            get_settings_for_sso_op(op_name)["CACHE_DJANGO_BACKEND"]
        ]
        self.op_name = op_name

    def get_key(self, key):
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
        result = OIDCSession.objects.filter(uid=uid).values_list("sid", flat=True)
        logger.debug(f"Fetched the following sid : {result} for {uid=}")

        return result

    def get_by_sub(self, sub: str) -> List[str]:
        result = OIDCSession.objects.filter(sub=sub).values_list("sid", flat=True)
        logger.debug(f"Fetched fhe following sid : {result} for {sub=}")
        return result

    def get(self, attr: str, val: str) -> List[str]:
        logger.debug(f"Fetch SID for sessions where [{attr}] = {val}")
        raise NotImplementedError(
            "Current session implementation does not support this method"
        )
