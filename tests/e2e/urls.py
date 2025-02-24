from django.contrib.auth.models import User
from django.urls import include, path
from rest_framework import routers, serializers, viewsets
from rest_framework.permissions import AllowAny

from django_pyoidc.views import (
    OIDCBackChannelLogoutView,
    OIDCCallbackView,
    OIDCLoginView,
    OIDCLogoutView,
)
from tests.e2e.test_app.models import Public
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


class PublicSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Public
        fields = ["data"]


# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


# ViewSets define the view behavior.
class PublicViewSet(viewsets.ModelViewSet):
    queryset = Public.objects.all()
    permission_classes = [AllowAny]
    serializer_class = PublicSerializer


# Routers provide an easy way of automatically determining the URL conf.
apirouter = routers.DefaultRouter()
apirouter.register(r"users", UserViewSet)
apirouter.register(r"publics", PublicViewSet)

urlpatterns = [
    path("login-1/", OIDCLoginView.as_view(op_name="sso1"), name="e2e_test_login_1"),
    path("login-2/", OIDCLoginView.as_view(op_name="sso2"), name="e2e_test_login_2"),
    path("login-3/", OIDCLoginView.as_view(op_name="sso3"), name="e2e_test_login_3"),
    path("login-4/", OIDCLoginView.as_view(op_name="sso4"), name="e2e_test_login_4"),
    path("login-5/", OIDCLoginView.as_view(op_name="sso5"), name="e2e_test_login_5"),
    path(
        "login-ll-1/",
        OIDCLoginView.as_view(op_name="lemon1"),
        name="e2e_test_ll_login_1",
    ),
    path(
        "callback-1/",
        OIDCCallbackView.as_view(op_name="sso1"),
        name="e2e_test_callback_1",
    ),
    path(
        "callback-2/",
        OIDCCallbackView.as_view(op_name="sso2"),
        name="e2e_test_callback_2",
    ),
    path(
        "callback-3/",
        OIDCCallbackView.as_view(op_name="sso3"),
        name="e2e_test_callback_3",
    ),
    path(
        "callback-4/",
        OIDCCallbackView.as_view(op_name="sso4"),
        name="e2e_test_callback_4",
    ),
    path(
        "callback-5/",
        OIDCCallbackView.as_view(op_name="sso5"),
        name="e2e_test_callback_5",
    ),
    path(
        "callback-ll-1/",
        OIDCCallbackView.as_view(op_name="lemon1"),
        name="e2e_test_callback_ll_1",
    ),
    path(
        "logout-1/",
        OIDCLogoutView.as_view(op_name="sso1"),
        name="e2e_test_logout_1",
    ),
    path(
        "logout-2/",
        OIDCLogoutView.as_view(op_name="sso2"),
        name="e2e_test_logout_2",
    ),
    path(
        "logout-3/",
        OIDCLogoutView.as_view(op_name="sso3"),
        name="e2e_test_logout_3",
    ),
    path(
        "logout-4/",
        OIDCLogoutView.as_view(op_name="sso4"),
        name="e2e_test_logout_4",
    ),
    path(
        "logout-5/",
        OIDCLogoutView.as_view(op_name="sso5"),
        name="e2e_test_logout_5",
    ),
    path(
        "logout-ll-1/",
        OIDCLogoutView.as_view(op_name="lemon1"),
        name="e2e_test_ll_logout_1",
    ),
    path(
        "back_channel_logout-1/",
        OIDCBackChannelLogoutView.as_view(op_name="sso1"),
        name="e2e_test_blogout_1",
    ),
    path(
        "back_channel_logout-2/",
        OIDCBackChannelLogoutView.as_view(op_name="sso2"),
        name="e2e_test_blogout_2",
    ),
    path(
        "back_channel_logout-3/",
        OIDCBackChannelLogoutView.as_view(op_name="sso3"),
        name="e2e_test_blogout_3",
    ),
    path(
        "back_channel_logout-4/",
        OIDCBackChannelLogoutView.as_view(op_name="sso4"),
        name="e2e_test_blogout_4",
    ),
    path(
        "back_channel_logout-5/",
        OIDCBackChannelLogoutView.as_view(op_name="sso5"),
        name="e2e_test_blogout_5",
    ),
    path(
        "test-success-1/",
        OIDCTestSuccessView.as_view(op_name="sso1"),
        name="e2e_test_success_1",
    ),
    path(
        "test-success-2/",
        OIDCTestSuccessView.as_view(op_name="sso2"),
        name="e2e_test_success_2",
    ),
    path(
        "test-success-3/",
        OIDCTestSuccessView.as_view(op_name="sso3"),
        name="e2e_test_success_3",
    ),
    path(
        "test-success-4/",
        OIDCTestSuccessView.as_view(op_name="sso4"),
        name="e2e_test_success_4",
    ),
    path(
        "test-success-5/",
        OIDCTestSuccessView.as_view(op_name="sso5"),
        name="e2e_test_success_5",
    ),
    path(
        "test-ll-success-1/",
        OIDCTestSuccessView.as_view(op_name="lemon1"),
        name="e2e_test_ll_success_1",
    ),
    path(
        "test-logout-done-1/",
        OIDCTestLogoutView.as_view(op_name="sso1"),
        name="e2e_test_logout_done_1",
    ),
    path(
        "test-logout-done-2/",
        OIDCTestLogoutView.as_view(op_name="sso2"),
        name="e2e_test_logout_done_2",
    ),
    path(
        "test-logout-done-3/",
        OIDCTestLogoutView.as_view(op_name="sso3"),
        name="e2e_test_logout_done_3",
    ),
    path(
        "test-logout-done-4/",
        OIDCTestLogoutView.as_view(op_name="sso4"),
        name="e2e_test_logout_done_4",
    ),
    path(
        "test-logout-done-5/",
        OIDCTestLogoutView.as_view(op_name="sso5"),
        name="e2e_test_logout_done_5",
    ),
    path(
        "test-ll-logout-done-1/",
        OIDCTestLogoutView.as_view(op_name="lemon1"),
        name="e2e_test_ll_logout_done_1",
    ),
    path(
        "test-failure-1/",
        OIDCTestFailureView.as_view(op_name="sso1"),
        name="e2e_test_failure_1",
    ),
    path(
        "test-failure-2/",
        OIDCTestFailureView.as_view(op_name="sso2"),
        name="e2e_test_failure_2",
    ),
    path(
        "test-failure-3/",
        OIDCTestFailureView.as_view(op_name="sso3"),
        name="e2e_test_failure_3",
    ),
    path(
        "test-failure-4/",
        OIDCTestFailureView.as_view(op_name="sso4"),
        name="e2e_test_failure_4",
    ),
    path(
        "test-failure-5/",
        OIDCTestFailureView.as_view(op_name="sso5"),
        name="e2e_test_failure_5",
    ),
    path(
        "test-ll-failure-1/",
        OIDCTestFailureView.as_view(op_name="lemon1"),
        name="e2e_test_ll_failure_1",
    ),
    path("api/", include(apirouter.urls)),
]
