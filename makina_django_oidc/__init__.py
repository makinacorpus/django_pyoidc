from typing import Dict

from django.contrib.auth import get_user_model
from oic.oic import IdToken


def get_user_by_email(userinfo_token: Dict[str, str], id_token: IdToken):
    User = get_user_model()

    username = ""
    id_token_claims = id_token.to_dict()

    if "preferred_username" in id_token_claims:
        username = id_token_claims["preferred_username"]
    elif "preferred_username" in userinfo_token:
        username = userinfo_token["preferred_username"]
    else:
        username = userinfo_token["email"]

    user, created = User.objects.get_or_create(
        email=userinfo_token["email"],
        username=username,
    )
    user.backend = "django.contrib.auth.backends.ModelBackend"
    return user
