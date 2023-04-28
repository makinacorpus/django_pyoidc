# Makina Django OIDC

This library allow *Single Sign On* (SSO) integration into Django through the [Open ID Connect (OIDC)]() protocol.

It can be used to setup a Single Sign On using an identity provider (Keycloak, etc.) or to login using Google, Twitter, etc.

**Warning** : this library has not been audited. However, we are based on [pyoidc](https://github.com/CZ-NIC/pyoidc/) which we believe is a sane OIDC implementation.

## Features

- Easy configuration through premade [`Provider`]() classes.
- Multiple provider support
- Easy integration with the [Django permission system]()
- Highly customizable design that should suit most needs
- Back-channel Logout
- Sane and secure defaults settings

## Roadmap

- `Bearer` authentication support for `django-rest-framework` integration
- Frontchannel logout

## Acknowledgement

This library is built on the work of many others. First all, thanks to all the maintainers of [pyoidc](https://github.com/CZ-NIC/pyoidc/) as they did all the spec implementation. This library is mostly about glue between Django and *pyoidc*.

We were also heavily inspired by :

* [`mozilla-django-oidc`](https://github.com/mozilla/mozilla-django-oidc) for it's login redirection URI management
* [`django-auth-oidc`](https://gitlab.com/aiakos/django-auth-oidc) for it's hook system

If you want to understand why we decided to implement our own library, this is documented [here]().

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

Now you can pick an identity provider from the [available providers](). Providers class are a quick way to generate the library configuration and URLs for a givenv identity provider. You can also use [manual set] if you wish.

Create a file named `oidc.py` next to your settings file and initialize your provider there :

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

## Appendix

- [Development instructions](./DEVELOPMENT.md)

## Commercial support

This project is sponsored by Makina Corpus. If you require assistance on your project(s), please contact us: contact@makina-corpus.com

## Report a security vulnerability

## License

[GPL](./LICENSE)


## Authors

- [@gbip](https://www.github.com/gbip)

