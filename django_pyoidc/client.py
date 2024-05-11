import logging

# import oic
from oic.extension.client import Client as ClientExtension
from oic.oic.consumer import Consumer
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from django_pyoidc.session import OIDCCacheSessionBackendForDjango
from django_pyoidc.utils import OIDCCacheBackendForDjango, get_setting_for_sso_op

logger = logging.getLogger(__name__)


class OIDCClient:
    def __init__(self, op_name, session_id=None):
        self._op_name = op_name

        self.session_cache_backend = OIDCCacheSessionBackendForDjango(self._op_name)
        self.general_cache_backend = OIDCCacheBackendForDjango(self._op_name)

        consumer_config = {
            # "debug": True,
            "response_type": "code"
        }

        client_config = {
            "client_id": get_setting_for_sso_op(op_name, "OIDC_CLIENT_ID"),
            "client_authn_method": CLIENT_AUTHN_METHOD,
        }

        self.consumer = Consumer(
            session_db=self.session_cache_backend,
            consumer_config=consumer_config,
            client_config=client_config,
        )
        # used in token introspection
        self.client_extension = ClientExtension(**client_config)

        provider_info_uri = get_setting_for_sso_op(
            op_name, "OIDC_PROVIDER_DISCOVERY_URI"
        )
        client_secret = get_setting_for_sso_op(op_name, "OIDC_CLIENT_SECRET")
        self.client_extension.client_secret = client_secret

        if session_id:
            self.consumer.restore(session_id)
        else:

            cache_key = self.general_cache_backend.generate_hashed_cache_key(
                provider_info_uri
            )
            try:
                config = self.general_cache_backend[cache_key]
            except KeyError:
                config = self.consumer.provider_config(provider_info_uri)
                # shared microcache for provider config
                # FIXME: Setting for duration
                self.general_cache_backend.set(cache_key, config, 60)
            self.consumer.client_secret = client_secret
