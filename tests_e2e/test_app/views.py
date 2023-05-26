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
        super().get(request, *args, **kwargs)
        messages.success(request, f"message: {request.user.email} is logged in.")

        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request))


class OIDCTestFailureView(OIDCView):
    """
    Used in e2e tests to validate login failures.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)
        messages.error(request, "message: something went bad.")

        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request))


class OIDCTestLogoutView(OIDCView):
    """
    Used in e2e tests to validate logout of a user.

    """

    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        super().get(request, *args, **kwargs)
        messages.success(request, "message: post logout view.")

        template = loader.get_template("tests.html")
        return HttpResponse(template.render(request=request))
