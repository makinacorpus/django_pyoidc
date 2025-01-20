from django.urls import include, path

from django_pyoidc.helper import OIDCHelper
from django_pyoidc.views import (
    OIDCBackChannelLogoutView,
    OIDCCallbackView,
    OIDCLoginView,
    OIDCLogoutView,
)

helper10 = OIDCHelper(op_name="sso10")
helper11 = OIDCHelper(op_name="sso11")
helper12 = OIDCHelper(op_name="sso12")
helper13 = OIDCHelper(op_name="sso13")
urlpatterns = [
    path("login-xyz/", OIDCLoginView.as_view(op_name="sso1"), name="test_login"),
    path("login-wtf/", OIDCLoginView.as_view(op_name="sso2"), name="test_login_2"),
    path(
        "callback-xyz/",
        OIDCCallbackView.as_view(op_name="sso1"),
        name="my_test_callback",
    ),
    path(
        "callback-wtf/",
        OIDCCallbackView.as_view(op_name="sso2"),
        name="my_test_callback_sso2",
    ),
    path(
        "logout-xyz/",
        OIDCLogoutView.as_view(op_name="sso1"),
        name="test_logout",
    ),
    path(
        "back_channel_logout-xyz/",
        OIDCBackChannelLogoutView.as_view(op_name="sso1"),
        name="test_blogout",
    ),
    path(
        "",
        include(
            (helper10.get_urlpatterns(), "django_pyoidc"), namespace="op10_namespace"
        ),
    ),
    path(
        "prefix11/",
        include(
            (helper11.get_urlpatterns(), "django_pyoidc"), namespace="op11_namespace"
        ),
    ),
    path(
        "prefix12/",
        include(
            (helper12.get_urlpatterns(), "django_pyoidc"), namespace="op12_namespace"
        ),
    ),
    path(
        "prefix13/",
        include(
            (helper13.get_urlpatterns(), "django_pyoidc"), namespace="op13_namespace"
        ),
    ),
]
