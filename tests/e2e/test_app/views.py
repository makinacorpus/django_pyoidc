import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.template import loader
from django.utils.decorators import method_decorator
from django.views import View

from django_pyoidc.views import OIDCView

logger = logging.getLogger(__name__)


class OIDCTestAppMixin:
    def build_context(self):
        """
        Feed the rights urls for theming context.
        """
        op_name = self.get_setting("op_name")
        if op_name[:5] == "lemon":
            number = op_name[-1]
            context = {
                "op_login_url": f"lemon{number}_namespace:lemon{number}-login",
                "op_logout_url": f"lemon{number}_namespace:lemon{number}-logout",
            }
        else:
            number = op_name[-1]
            context = {
                "op_login_url": f"e2e_test_login_{number}",
                "op_logout_url": f"e2e_test_logout_{number}",
            }
        return context


@method_decorator(
    login_required,
    name="dispatch",
)
class OIDCProtectedView(View):
    """
    Used in e2e tests to validate access restricted on valid sessions.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        if request.user:
            messages.success(request, f"message: {request.user.email} is viewing protected page.")
        else:
            messages.success(request, f"message: someone is viewing protected page.")
        context = {
                "op_login_url": f"e2e_test_login_1",
                "op_logout_url": f"e2e_test_logout_1",
        }
        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request, context=context))


class OIDCTestSuccessView(OIDCView, OIDCTestAppMixin):
    """
    Used in e2e tests to validate login of a user.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        messages.success(request, f"message: {request.user.email} is logged in.")
        context = self.build_context()
        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request, context=context))


class OIDCTestFailureView(OIDCView, OIDCTestAppMixin):
    """
    Used in e2e tests to validate login failures.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        messages.error(request, "message: something went bad.")
        context = self.build_context()
        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request, context=context))


class OIDCTestLogoutView(OIDCView, OIDCTestAppMixin):
    """
    Used in e2e tests to validate logout of a user.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        messages.success(request, "message: post logout view.")
        context = self.build_context()
        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request, context=context))
