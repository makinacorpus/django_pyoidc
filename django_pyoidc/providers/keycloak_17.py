from django_pyoidc.providers.keycloak_10 import Keycloak10Provider


class Keycloak17Provider(Keycloak10Provider):
    """
    Provide Django settings/urlconf based on keycloak behaviour (v17)
    """
