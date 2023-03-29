from django.urls import path

from makina_django_oidc.views import OIDCCallbackView, OIDCLoginView, OIDCLogoutView

urlpatterns = [
    path("login/", OIDCLoginView.as_view(op_name="test"), name="test_login"),
    path(
        "callback/",
        OIDCCallbackView.as_view(op_name="test"),
        name="test_callback",
    ),
    path(
        "logout/",
        OIDCLogoutView.as_view(op_name="test"),
        name="test_logout",
    ),
]
