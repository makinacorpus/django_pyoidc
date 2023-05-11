from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied


def login_callback(request, user):
    messages.success(request, f"login_callback for : {user.email}")


def logout_callback(request, logout_request_args):
    messages.success(request, f"Logout Callback for {request.user.email}.")
    logout_request_args["locale"] = "fr"
    logout_request_args["test"] = "zorg"
    return logout_request_args


def get_user(userinfo_token, access_token, id_token):

    print("userinfo_token")
    print(type(userinfo_token))
    print(userinfo_token)
    print("access_token")
    print(type(access_token))
    print(access_token)
    print("id_token")
    print(type(id_token))
    print(id_token)

    audiences = []
    if "aud" in id_token:
        if type(id_token["aud"] is str):
            audiences = [
                id_token["aud"],
            ]
        elif type(id_token["aud"] is bytes):
            audiences = ([id_token["aud"].decode("ascii")],)
        elif type(id_token["aud"] is list):
            audiences = id_token["aud"]

    # Perform audience check
    if settings.MAKINA_DJANGO_OIDC["sso1"]["CLIENT_ID"] not in audiences:
        raise PermissionDenied("You do not have access to this application.")

    User = get_user_model()
    user, created = User.objects.get_or_create(email=userinfo_token["email"])
    user.is_superuser = (
        "groups" in userinfo_token and "admins" in userinfo_token["groups"]
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    user.save()

    return user
