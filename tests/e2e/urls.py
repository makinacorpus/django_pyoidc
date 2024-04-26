from django.contrib.auth.models import User
from django.urls import include, path
from rest_framework import routers, serializers, viewsets

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


# DRF tests ----
# Serializers define the API representation.
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ["url", "username", "email", "is_staff"]


# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


# Routers provide an easy way of automatically determining the URL conf.
apirouter = routers.DefaultRouter()
apirouter.register(r"users", UserViewSet)


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
        name="test_success",
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
    path("api", include(apirouter.urls)),
]
