# Makina Django OIDC

This library allow *Single Sign On* (SSO) integration into Django through the [Open ID Connect (OIDC)]() protocol.

It can be used to setup a Single Sign On using an identity provider (Keycloak, etc.) or to login using Google, Twitter, etc.


## Features

- Hook system to customize
- BackChannel Logout

## Documentation

The documentation is graciously hosted at [readthedocs]().

## Installation

First, install the python package :

```bash
pip install makina-django-doic
```

Then add the library app to your django applications, after `django.contrib.sessions` and `django.contrib.auth` :

```python
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.sessions",
    ...
    "makina-django-oidc"
]
```

Now you can pick an identity provider from the [available providers](). Create a file named `oidc.py` next to your settings file and initialize your provider there :

```python
from makina_django_oidc.providers.keycloak_20 import Keycloak20Provider

my_project_provider = Keycloak20Provider(
    op_name="keycloak",
    logout_redirect="http://app.local:8082/",
    failure_redirect="http://app.local:8082/",
    success_redirect="http://app.local:8082/",
    redirect_requires_https=False,
    client_secret="s3cret",
    client_id="my_client_id",
    keycloak_realm_uri="http://keycloak.local:8080/",
    keycloak_realm="Demo",
)
```

You can then add to your django configuration the following line :

```python
from .oidc_providers import my_project_provider

MAKINA_DJANGO_OIDC = {
    **my_project_provider.get_config(allowed_hosts=["app.local:8082"]),
}
```

Finally, add OIDC views to your url configuration (`urls.py`):

```python
from .oidc_providers import my_project_provider

urlpatterns = [
    path("auth", include(my_project_provider.get_urlpatterns())),
]
```

And you are ready to go !

## Usage/Examples

We wrote an extensive collection of 'how-to' guides in the [documentation]().

## Related

Here are some related projects

[Awesome README](https://github.com/matiassingers/awesome-readme)

## Appendix

- [Development instructions](./DEVELOPMENT.md)

## Support

If you need commercial support (new specific features, custom identity provider integration, etc.), you can always contact Makina Corpus administration at : contact@makina-corpus.com.

You may also open a ticket, but we can not guarantee that it will be handled in a timely maneer.

## License

[GPL](./LICENSE)


## Authors

- [@gbip](https://www.github.com/gbip)
- [@gbip](https://www.github.com/gbip)


