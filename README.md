# Makina Django OIDC


<p align="center">
<a href="https://django-pyoidc.readthedocs.io">
        <img src="https://readthedocs.org/projects/django-pyoidc/badge/?version=main" />
</a>
</p>

This library allow *Single Sign On* (SSO) integration into Django through the [Open ID Connect (OIDC)]() protocol.

It can be used to setup a Single Sign On using an identity provider (Keycloak, etc.) or to login using Google, Twitter, etc.

**Warning** : this library has not been audited. However, we are based on [pyoidc](https://github.com/CZ-NIC/pyoidc/) which we believe is a sane OIDC implementation.

## Features

- Easy configuration through premade [`Provider`](https://django-pyoidc.readthedocs.io/en/latest/user.html#providers) classes.
- Multiple provider support
- Easy integration with the [Django permission system](https://django-pyoidc.readthedocs.io/en/latest/how-to.html#use-the-django-permission-system-with-oidc)
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

If you want to understand why we decided to implement our own library, this is documented [here](https://django-pyoidc.readthedocs.io/en/latest/explanation.html#other-oidc-libraries).

## Documentation

The documentation is graciously hosted at [readthedocs](https://django-pyoidc.readthedocs.io).

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
    "django-pyoidc"
]
```

Don't forget to add the session middleware ! Add in your `settings.py` :

```python
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
]
```

Now is time to run a migrate operation, as we create a database table ([read why here](https://django-pyoidc.readthedocs.io/en/latest/explanation.html#cache-management)). Run in your project dir :

```
./manage.py migrate
```

We also need a cache ([read why here](https://django-pyoidc.readthedocs.io/en/latest/explanation.html#cache-management)), so let's configure a dumb one for development purposes. Add in your `settings.py` :

```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-snowflake",
    }
}
```

Now you can pick an identity provider from the [available providers](https://django-pyoidc.readthedocs.io/en/latest/user.html#providers). Providers class are a quick way to generate the library configuration and URLs for a givenv identity provider. You can also use [manual set] if you wish.

Create a file named `oidc.py` next to your settings file and initialize your provider there :

```python
from django_pyoidc.providers.keycloak import KeycloakProvider

my_oidc_provider = KeycloakProvider(
    op_name="keycloak",
    client_secret="s3cret",
    client_id="my_client_id",
    keycloak_base_uri="http://keycloak.local:8080/auth/", # we use the auth/ path prefix option on Keycloak
    keycloak_realm="Demo",
    logout_redirect="http://app.local:8082/",
    failure_redirect="http://app.local:8082/",
    success_redirect="http://app.local:8082/",
    redirect_requires_https=False,
)
```

You can then add to your django configuration the following line :

```python
from .oidc_providers import my_oidc_provider

DJANGO_PYOIDC = {
    **my_oidc_provider.get_config(allowed_hosts=["app.local:8082"]),
}
```

Finally, add OIDC views to your url configuration (`urls.py`):

```python
from .oidc_providers import my_oidc_provider

urlpatterns = [
    path("auth", include(my_oidc_provider.get_urlpatterns())),
]
```

And you are ready to go !

If you struggle with those instructions, take a look at [the quickstart tutorial](https://django-pyoidc.readthedocs.io/en/latest/tutorial.html#getting-started).

## Usage/Examples

We wrote an extensive collection of 'how-to' guides in the [documentation](https://django-pyoidc.readthedocs.io/en/latest/how-to.html).

## Appendix

- [Development instructions](./DEVELOPMENT.md)

## Commercial support

This project is sponsored by Makina Corpus. If you require assistance on your project(s), please contact us: contact@makina-corpus.com

## Report a security vulnerability

## License

[GPL](./LICENSE)


## Authors

- [@gbip](https://www.github.com/gbip)
- [@regilero](https://github.com/regilero)

