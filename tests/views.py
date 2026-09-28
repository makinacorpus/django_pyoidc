from typing import Any

from django.contrib.auth.decorators import login_not_required, login_required
from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views import View


@method_decorator(
    login_not_required,
    name="dispatch",
)
class AnonymousView(View):
    """
    When receiving a GET or POST request, this views sends an hello world.
    """

    http_method_names = ["get", "post"]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return HttpResponse("Hello world!")

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return HttpResponse("Hello world!")


@method_decorator(
    login_required,
    name="dispatch",
)
class AuthentifiedView(View):
    """
    When receiving a GET or POST request, this views sends an hello world if you're authentified.
    """

    http_method_names = ["get", "post"]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return HttpResponse("Hello world!")

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        return HttpResponse("Hello world!")
