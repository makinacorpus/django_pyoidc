from django_pyoidc.providers.keycloak_18 import Keycloak18Provider


class KeycloakProvider(Keycloak18Provider):
    """
    Provide django settings/urlconf based on keycloak behaviour (latest version).

    For older Keycloak versions please check the other Keycloak_* providers.
    """

    pass
