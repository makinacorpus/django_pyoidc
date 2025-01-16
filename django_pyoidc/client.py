import logging
from typing import Optional, TypeVar, Union

# import oic
from oic.extension.client import Client as ClientExtension
from oic.oic.consumer import Consumer
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from django_pyoidc.exceptions import (
    InvalidOIDCConfigurationException,
    InvalidSIDException,
)
from django_pyoidc.session import OIDCCacheSessionBackendForDjango
from django_pyoidc.settings import OIDCSettings, OIDCSettingsFactory, OidcSettingValue
from django_pyoidc.utils import OIDCCacheBackendForDjango

logger = logging.getLogger(__name__)

T = TypeVar("T")


class OIDCClient:
    def __init__(self, op_name: str, session_id: Optional[str] = None):
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
        )  # type: ignore[no-untyped-call] # oic.oic.consumer.Consumer is not typed yet

        # used in token introspection
        self.client_extension = ClientExtension(**client_config)  # type: ignore[no-untyped-call] # oic.extension.client.Client is not typed yet

        provider_discovery_uri: str = self.opsettings.get("provider_discovery_uri", None)  # type: ignore[assignment] # we can assume that the configuration is ok
        self.client_extension.client_secret = client_secret

        if session_id is not None:
            try:
                self.consumer.restore(session_id)  # type: ignore[no-untyped-call] # Consumer.restore is not typed yet
            except KeyError:
                # This is an error as for example during the first communication round trips between
                # the op and the client we'll have to find state elements in the oidc session
                raise InvalidSIDException(
                    f"OIDC consumer failed to restore oidc session {session_id}."
                )
            return

        if provider_discovery_uri is None:
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
                    self.consumer.handle_provider_config(config, provider_discovery_uri)  # type: ignore[arg-type] # provider_discovery_uri is from the cache
                except KeyError:
                    # This make an HTTP call on provider discovery uri
                    config = self.consumer.provider_config(provider_discovery_uri)
                    # shared microcache for provider config
                    ttl: int = self.opsettings.get("oidc_cache_provider_metadata_ttl")  # type: ignore[assignment] # we can assume the configuration is right
                    self.general_cache_backend.set(
                        cache_key,
                        config,
                        ttl,
                    )
            else:
                # This make an HTTP call on provider discovery uri
                self.consumer.provider_config(provider_discovery_uri)
        self.consumer.client_secret = client_secret

    def get_settings(self) -> OIDCSettings:
        return self.opsettings

    def get_setting(
        self, name: str, default: Optional[T] = None
    ) -> Optional[Union[OidcSettingValue, T]]:
        return self.opsettings.get(name, default)
