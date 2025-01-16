# type: ignore
import datetime

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from rest_framework import authentication, exceptions

from django_pyoidc.utils import OIDCCacheBackendForDjango
from django_pyoidc.views import OIDClient


class BaseOIDCAuthentication(authentication.BaseAuthentication):
    def __init__(self):
        # fixme : no multi-provider support here
        self.op_name = "default"
        self.general_cache_backend = OIDCCacheBackendForDjango(self.op_name)
        self.client = OIDClient(self.op_name)

    def authenticate(self, request):
        token = self.get_access_token(request)
        if token is None:
            return
        cache_key = self.general_cache_backend.generate_hashed_cache_key(token)
        try:
            access_token_claims = self.general_cache_backend["cache_key"]
        except KeyError:
            access_token_claims = self._introspect_access_token(token)
            if "active" not in access_token_claims:
                raise exceptions.AuthenticationFailed(
                    "Invalid identity provider reponse"
                )
            if not access_token_claims["active"]:
                raise exceptions.AuthenticationFailed("Account disabled")
            print(f"{access_token_claims=}")
            print(f"{token=}")
            # store it in cache
            current = datetime.datetime.now().strftime("%s")
            if "exp" not in access_token_claims:
                raise exceptions.AuthenticationFailed(
                    "No expiry set on the access token."
                )
            access_token_expiry = access_token_claims["exp"]
            exp = int(access_token_expiry) - int(current)
            self.general_cache_backend.set(cache_key, access_token_claims, exp)
        return self.get_user(token, access_token_claims), None

    def _introspect_access_token(self, token):
        request_args = {
            "token": token,
            "token_type_hint": "access_token",
        }
        client_auth_method = self.client.consumer.registration_response.get(
            "introspection_endpoint_auth_method", "client_secret_basic"
        )
        introspection = self.client.client_extension.do_token_introspection(
            request_args=request_args,
            authn_method=client_auth_method,
            endpoint=self.client.consumer.introspection_endpoint,
            # http_args={"headers" : {"content-type":"application/x-www-form-urlencoded"}}
        )
        print(f"{introspection=}")
        return introspection.to_dict()

    def get_access_token(self, request):
        # fixme : hardcoded header key in the following function call
        header = authentication.get_authorization_header(request)
        if not header:
            return None
        header = header.decode(authentication.HTTP_HEADER_ENCODING)
        print(f"{header=}")
        return header

    def get_user(self, token: str, access_token_claims) -> AbstractUser:
        raise NotImplementedError(
            f"Do no use {self.__class__.__name__} directly : inherit from it"
            f"and override get_user()"
        )


class DefaultOIDCAuthentication(BaseOIDCAuthentication):
    def get_user(self, token: str, access_token_claims) -> AbstractUser:
        User = get_user_model()
        user, _ = User.objects.get_or_create(id=token["sub"])
        return user
