import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

try:
    from drf_spectacular.extensions import OpenApiAuthenticationExtension

    from django_pyoidc.utils import get_setting_for_sso_op

    class OIDCScheme(OpenApiAuthenticationExtension):
        target_class = "django_pyoidc.drf.authentication.OIDCBearerAuthentication"
        name = "openIdConnect"
        match_subclasses = True
        priority = -1

        def get_security_definition(self, auto_schema):
            from django_pyoidc.drf.authentication import OIDCBearerAuthentication

            op = OIDCBearerAuthentication.extract_drf_opname()
            well_known_url = get_setting_for_sso_op(op, "OIDC_PROVIDER_DISCOVERY_URI")
            if not well_known_url.endswith(".well-known/openid-configuration"):
                if not well_known_url.endswith("/"):
                    well_known_url += "/"
                well_known_url = urljoin(
                    well_known_url, ".well-known/openid-configuration"
                )

            header_name = get_setting_for_sso_op(op, "OIDC_API_BEARER_NAME", "Bearer")
            if header_name != "Bearer":
                logger.warning(
                    "The configuration for 'OIDC_API_BEARER_NAME' will cause issue with swagger UI :"
                    "it is not yet possible to change the header name for swagger UI, you should stick to"
                    "'Bearer'."
                )
            return {
                "type": "openIdConnect",
                "openIdConnectUrl": well_known_url,
            }

except ImportError:
    logger.debug(
        "The package 'drf-spectacular' is not installed, skipping schema generation."
    )
