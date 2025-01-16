from typing import Any, Dict

from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation

from django_pyoidc.exceptions import ClaimNotFoundError
from django_pyoidc.utils import extract_claim_from_tokens


def get_user_by_email(tokens: Dict[str, Any]) -> Any:
    User = get_user_model()

    username = None
    preferred_username = None
    email = None
    client_host = None
    client_address = None
    client_id = None
    django_username = None

    try:
        email = extract_claim_from_tokens("email", tokens)
    except ClaimNotFoundError:
        pass

    try:
        preferred_username = extract_claim_from_tokens("preferred_username", tokens)
    except ClaimNotFoundError:
        pass

    try:
        username = extract_claim_from_tokens("username", tokens)
    except ClaimNotFoundError:
        pass

    if preferred_username is None:
        if username is None:
            if email:
                django_username = email
            else:
                raise SuspiciousOperation(
                    "Cannot extract username or email from available OIDC tokens."
                )
        else:
            django_username = username
    else:
        django_username = preferred_username

    # Currently client Credential logins in Keycloak adds these mappers in access tokens.
    # we can use that to detect M2M accounts.
    # TODO: check if any other mapper can/should be used for other providers
    try:
        client_host = extract_claim_from_tokens("clientHost", tokens)
    except ClaimNotFoundError:
        pass
    try:
        client_address = extract_claim_from_tokens("clientAddress", tokens)
    except ClaimNotFoundError:
        pass

    if email is None and client_host is not None and client_address is not None:
        # that's a M2M connexion in grant=client_credential mode
        try:
            client_id = extract_claim_from_tokens("client_id", tokens)
        except ClaimNotFoundError:
            client_id = django_username
        # Build a fake email for the service accounts
        email = f"{client_id}@localhost.lan"

    user, created = User.objects.get_or_create(
        email=email,
        username=django_username,
    )
    if hasattr(user, "backend"):
        user.backend = "django.contrib.auth.backends.ModelBackend"
    return user
