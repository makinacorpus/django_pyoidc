import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied

from django_pyoidc.client import OIDCClient

logger = logging.getLogger(__name__)


def login_callback(request, user):
    messages.success(request, f"login_callback for : {user.email}")


def logout_callback(request, logout_request_args):
    if request.user.is_anonymous:
        messages.success(request, "Logout Callback for anonymous user.")
    else:
        messages.success(request, f"Logout Callback for {request.user.email}.")

    logout_request_args["locale"] = "fr"
    logout_request_args["test"] = "zorg"
    return logout_request_args


def _debug_tokens(tokens={}):
    print("++++++++ TOKENS DEBUG ++++++++++++++++")
    if "info_token_claims" in tokens:
        print("info_token_claims")
        print(type(tokens["info_token_claims"]))  # dict
        print(tokens["info_token_claims"])

    if "access_token_jwt" in tokens:
        print("access_token_jwt")
        print(tokens["access_token_jwt"])
        print(type(tokens["access_token_jwt"]))  # <class 'str'>

    if "access_token_claims" in tokens:
        print("access_token_claims")
        print(
            type(tokens["access_token_claims"])
        )  # oic.extension.message.TokenIntrospectionResponse
        print(tokens["access_token_claims"])

    if "id_token_claims" in tokens:
        print(type(tokens["id_token_claims"]))  # dict
        print(tokens["id_token_claims"])


def get_user_with_resource_access_check(tokens={}):

    _debug_tokens(tokens)
    access_token_claims = (
        tokens["access_token_claims"] if "access_token_claims" in tokens else None
    )
    id_token_claims = tokens["id_token_claims"] if "id_token_claims" in tokens else None
    info_token_claims = (
        tokens["info_token_claims"] if "info_token_claims" in tokens else None
    )

    resource_access = (
        access_token_claims["resource_access"]
        if "resource_access" in access_token_claims
        else None
    )

    # Perform resource access checks
    # FIXME: not sure we are always used with sso1, needa way to retrieve current op_name
    # maybe from the request session, but then the request should be given as arg of user hook.
    client_id = settings.DJANGO_PYOIDC["sso1"]["client_id"]
    # warning for user with no access Keycloak would not generate the resource_access claim
    # so we need to check absence of the claim also
    if (resource_access and client_id not in resource_access) or (
        resource_access is None
    ):
        logger.error("Failed resource access check in access_token")
        raise PermissionDenied("You do not have access to this application.")
    # then you could extend roles analysis if needed (for example this could need a local groups/roles mapping)
    # else
    # roles = resource_access[client_id]
    # if 'AccessApp1' in roles:
    #     do stuff

    username = ""

    if "preferred_username" in id_token_claims:
        username = id_token_claims["preferred_username"]
    elif "preferred_username" in info_token_claims:
        username = info_token_claims["preferred_username"]
    else:
        username = info_token_claims["email"]

    User = get_user_model()
    user, created = User.objects.get_or_create(
        email=info_token_claims["email"],
        username=username,
    )
    user.is_superuser = (
        "groups" in info_token_claims and "admins" in info_token_claims["groups"]
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    user.save()

    return user


def get_user_with_minimal_audiences_check(tokens={}):

    _debug_tokens(tokens)
    access_token_claims = (
        tokens["access_token_claims"] if "access_token_claims" in tokens else None
    )
    id_token_claims = tokens["id_token_claims"] if "id_token_claims" in tokens else None
    info_token_claims = (
        tokens["info_token_claims"] if "info_token_claims" in tokens else None
    )

    # Perform a minimal audience check
    # Note: here not checking if client_id is in 'aud' because that's broken in Keycloak
    client_id = settings.DJANGO_PYOIDC["sso1"]["client_id"]
    if "azp" not in access_token_claims:
        logger.error("Missing azp claim access_token")
        raise PermissionDenied("You do not have access to this application.")
    elif not access_token_claims["azp"] == client_id:
        logger.error("Failed audience (azp claim) minimal check in access_token")
        raise PermissionDenied("You do not have access to this application.")

    username = ""

    if "preferred_username" in id_token_claims:
        username = id_token_claims["preferred_username"]
    elif "preferred_username" in info_token_claims:
        username = info_token_claims["preferred_username"]
    else:
        username = info_token_claims["email"]

    User = get_user_model()
    user, created = User.objects.get_or_create(
        email=info_token_claims["email"],
        username=username,
    )
    user.is_superuser = (
        "groups" in info_token_claims and "admins" in info_token_claims["groups"]
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    user.save()

    return user


def get_user_with_audiences_check(tokens={}):

    _debug_tokens(tokens)
    access_token_claims = (
        tokens["access_token_claims"] if "access_token_claims" in tokens else None
    )
    id_token_claims = tokens["id_token_claims"] if "id_token_claims" in tokens else None
    info_token_claims = (
        tokens["info_token_claims"] if "info_token_claims" in tokens else None
    )

    # Note: Keycloak broke the audience checks for access_tokens, an access token generated by "X" request
    # will not contain "X" in the 'aud' key, only extra audiences.
    # so with keycloak you can only perform audiences checks when receiving access tokens generated
    # by other means (like by a front)
    audiences = []
    if "aud" in access_token_claims:
        if type(access_token_claims["aud"]) is str:
            audiences = [
                access_token_claims["aud"],
            ]
        elif type(access_token_claims["aud"]) is bytes:
            audiences = [
                access_token_claims["aud"].decode("ascii"),
            ]
        elif type(access_token_claims["aud"]) is list:
            audiences = access_token_claims["aud"]
        else:
            raise RuntimeError("Unknown type for audience claim")

    # Perform audience check
    if audiences and settings.DJANGO_PYOIDC["sso1"]["client_id"] not in audiences:
        logger.error("Failed audience check in access_token")
        raise PermissionDenied("You do not have access to this application.")

    username = ""

    if "preferred_username" in id_token_claims:
        username = id_token_claims["preferred_username"]
    elif "preferred_username" in info_token_claims:
        username = info_token_claims["preferred_username"]
    else:
        username = info_token_claims["email"]

    User = get_user_model()
    user, created = User.objects.get_or_create(
        email=info_token_claims["email"],
        username=username,
    )
    user.is_superuser = (
        "groups" in info_token_claims and "admins" in info_token_claims["groups"]
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    user.save()

    return user


def hook_validate_access_token(access_token_jwt: str, client: OIDCClient):
    """Here we should handle the jwt string and convert it to a claim dictionnary.

    But we should also ensure validity of the jwt (like signatures, expiration, etc.).
    """
    return {}
