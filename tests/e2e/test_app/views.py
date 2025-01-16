import logging

from django.contrib import messages
from django.http import HttpResponse
from django.template import loader

from django_pyoidc.views import OIDCView

logger = logging.getLogger(__name__)


class OIDCTestSuccessView(OIDCView):
    """
    Used in e2e tests to validate login of a user.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        messages.success(request, f"message: {request.user.email} is logged in.")

        op_name = self.get_setting("op_name")
        if op_name[:5] == "lemon":
            number = op_name[-1]
            context = {
                "op_login_url": f"e2e_test_ll_login_{number}",
                "op_logout_url": f"e2e_test_ll_logout_{number}",
            }
        else:
            number = op_name[-1]
            context = {
                "op_login_url": f"e2e_test_login_{number}",
                "op_logout_url": f"e2e_test_logout_{number}",
            }
        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request, context=context))


class OIDCTestFailureView(OIDCView):
    """
    Used in e2e tests to validate login failures.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        messages.error(request, "message: something went bad.")

        op_name = self.get_setting("op_name")
        if op_name[:5] == "lemon":
            number = op_name[-1]
            context = {
                "op_login_url": f"e2e_test_ll_login_{number}",
                "op_logout_url": f"e2e_test_ll_logout_{number}",
            }
        else:
            number = op_name[-1]
            context = {
                "op_login_url": f"e2e_test_login_{number}",
                "op_logout_url": f"e2e_test_logout_{number}",
            }

        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request, context=context))


class OIDCTestLogoutView(OIDCView):
    """
    Used in e2e tests to validate logout of a user.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        messages.success(request, "message: post logout view.")

        op_name = self.get_setting("op_name")
        if op_name[:5] == "lemon":
            number = op_name[-1]
            context = {
                "op_login_url": f"e2e_test_ll_login_{number}",
                "op_logout_url": f"e2e_test_ll_logout_{number}",
            }
        else:
            number = op_name[-1]
            context = {
                "op_login_url": f"e2e_test_login_{number}",
                "op_logout_url": f"e2e_test_logout_{number}",
            }
        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request, context=context))
