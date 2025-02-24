from django.urls import path

from django_pyoidc.views import (
    OIDCBackChannelLogoutView,
    OIDCCallbackView,
    OIDCLoginView,
    OIDCLogoutView,
)

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
]
