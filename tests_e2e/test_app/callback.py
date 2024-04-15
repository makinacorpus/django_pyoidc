import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied

logger = logging.getLogger(__name__)


def login_callback(request, user):
    messages.success(request, f"login_callback for : {user.email}")


def logout_callback(request, logout_request_args):
    messages.success(request, f"Logout Callback for {request.user.email}.")
    logout_request_args["locale"] = "fr"
    logout_request_args["test"] = "zorg"
    return logout_request_args


def get_user(userinfo_token, access_token, id_token_claims):

    print("++++++++++++++++++++++++")
    print("userinfo_token")
    print(type(userinfo_token))  # <class 'oic.oic.message.OpenIDSchema'>
    print(userinfo_token)
    print("access_token")
    print(type(access_token))  # <class 'str'>
    print(access_token)
    print("id_token")
    print(type(id_token_claims))  # dict
    print(id_token_claims)

    access_token_claims = (
        {}
    )  # FIXME: get access_token as dict here, from introspection maybe.
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

    print(audiences)
    print("++++++++++++++++++++++++")
    # Perform audience check
    if audiences and settings.DJANGO_PYOIDC["sso1"]["OIDC_CLIENT_ID"] not in audiences:
        logger.error("Failed audience check in id_token")
        raise PermissionDenied("You do not have access to this application.")

    username = ""

    if "preferred_username" in id_token_claims:
        username = id_token_claims["preferred_username"]
    elif "preferred_username" in userinfo_token:
        username = userinfo_token["preferred_username"]
    else:
        username = userinfo_token["email"]

    User = get_user_model()
    user, created = User.objects.get_or_create(
        email=userinfo_token["email"],
        username=username,
    )
    user.is_superuser = (
        "groups" in userinfo_token and "admins" in userinfo_token["groups"]
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    user.save()

    return user
