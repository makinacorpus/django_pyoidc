from django.urls import path

from django_pyoidc.views import (
    OIDCBackChannelLogoutView,
    OIDCCallbackView,
    OIDCLoginView,
    OIDCLogoutView,
)
from tests.e2e.test_app.views import (
    OIDCTestFailureView,
    OIDCTestLogoutView,
    OIDCTestSuccessView,
)

urlpatterns = [
    path("login/", OIDCLoginView.as_view(op_name="sso1"), name="test_login"),
    path(
        "callback/",
        OIDCCallbackView.as_view(op_name="sso1"),
        name="test_callback",
    ),
    path(
        "logout/",
        OIDCLogoutView.as_view(op_name="sso1"),
        name="test_logout",
    ),
    path(
        "back_channel_logout/",
        OIDCBackChannelLogoutView.as_view(op_name="sso1"),
        name="test_blogout",
    ),
    path(
        "test-success/",
        OIDCTestSuccessView.as_view(op_name="sso1"),
        name="test_sucess",
    ),
    path(
        "test-logout-done/",
        OIDCTestLogoutView.as_view(op_name="sso1"),
        name="test_logout_done",
    ),
    path(
        "test-failure/",
        OIDCTestFailureView.as_view(op_name="sso1"),
        name="test_failure",
    ),
]
