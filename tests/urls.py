from django.urls import path

from makina_django_oidc.views import OIDCCallbackView, OIDCLoginView, OIDCLogoutView

urlpatterns = [
    path("login/", OIDCLoginView.as_view(op_name="client1"), name="test_login"),
    path(
        "callback/",
        OIDCCallbackView.as_view(op_name="client1"),
        name="test_callback",
    ),
    path(
        "logout/",
        OIDCLogoutView.as_view(op_name="client1"),
        name="test_logout",
    ),
]
