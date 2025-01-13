import logging

# import oic
from oic.extension.client import Client as ClientExtension
from oic.oic.consumer import Consumer
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from django_pyoidc.exceptions import (
    InvalidOIDCConfigurationException,
    InvalidSIDException,
)
from django_pyoidc.session import OIDCCacheSessionBackendForDjango
from django_pyoidc.settings import OIDCSettings, OIDCSettingsFactory
from django_pyoidc.utils import OIDCCacheBackendForDjango

logger = logging.getLogger(__name__)


class OIDCClient:
    def __init__(self, op_name: str, session_id=None):
        self.opsettings = OIDCSettingsFactory.get(op_name)

        self.session_cache_backend = OIDCCacheSessionBackendForDjango(self.opsettings)
        self.general_cache_backend = OIDCCacheBackendForDjango(self.opsettings)
        client_id = self.opsettings.get("client_id")
        client_secret = self.opsettings.get("client_secret", None)
        consumer_config = self.opsettings.get(
            "client_consumer_config_dict",
            {
                # "debug": True,
                "response_type": "code"
            },
        )

        client_config = {
            "client_id": client_id,
            "client_authn_method": self.opsettings.get(
                "client_authn_method", CLIENT_AUTHN_METHOD
            ),
        }
        self.consumer = Consumer(
            session_db=self.session_cache_backend,
            consumer_config=consumer_config,
            client_config=client_config,
        )
        # used in token introspection
        self.client_extension = ClientExtension(**client_config)

        provider_discovery_uri = self.opsettings.get("provider_discovery_uri", None)
        self.client_extension.client_secret = client_secret

        if session_id:
            try:
                self.consumer.restore(session_id)
            except KeyError:
                # This is an error as for example during the first communication round trips between
                # the op and the client we'll have to find state elements in the oidc session
                raise InvalidSIDException(
                    f"OIDC consumer failed to restore oidc session {session_id}."
                )
            return

        if not provider_discovery_uri:
            raise InvalidOIDCConfigurationException(
                "No provider discovery uri provided."
            )
        else:
            if self.opsettings.get("oidc_cache_provider_metadata", False):
                cache_key = self.general_cache_backend.generate_hashed_cache_key(
                    provider_discovery_uri
                )
                try:
                    config = self.general_cache_backend[cache_key]
                    # this will for example register endpoints on the consumer object
                    self.consumer.handle_provider_config(config, provider_discovery_uri)
                except KeyError:
                    # This make an HTTP call on provider discovery uri
                    config = self.consumer.provider_config(provider_discovery_uri)
                    # shared microcache for provider config
                    # FIXME: Setting for duration
                    self.general_cache_backend.set(cache_key, config, 60)
            else:
                # This make an HTTP call on provider discovery uri
                config = self.consumer.provider_config(provider_discovery_uri)
        self.consumer.client_secret = client_secret

    def get_settings(self) -> OIDCSettings:
        return self.opsettings
