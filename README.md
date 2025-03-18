# django-pyoidc


<p align="center">
<a href="https://django-pyoidc.readthedocs.io">
        <img src="https://readthedocs.org/projects/django-pyoidc/badge/?version=stable&style=plastic"/>
</a>
<a href="https://pypi.org/project/django-pyoidc/">
  <img src="https://img.shields.io/pypi/v/django_pyoidc.svg"/>      
</a>
<a href="https://pypi.org/project/django-pyoidc/">
  <img src="https://img.shields.io/pypi/pyversions/django_pyoidc"/>      
</a>
<a href="https://pypi.org/project/django-pyoidc/">
  <img src="[https://img.shields.io/pypi/pyversions/django_pyoidc](https://img.shields.io/pypi/frameworkversions/django/django_pyoidc)"/>      
</a>


This library allow *Single Sign On* (SSO) integration into Django through the [Open ID Connect (OIDC)]() protocol.

It can be used to setup a Single Sign On using an identity provider (Keycloak, etc.) or to login using Google, Twitter, etc.

**Warning** : this library has not been audited. However, we are based on [pyoidc](https://github.com/CZ-NIC/pyoidc/) which we believe is a sane OIDC implementation.

We tried to make OpenID Connect (OIDC) configuration as easy and secure as possible. However 
everything can be customized, and we tried to take into account every use case in the library design.
If you are not satisfied with the default configuration, take a look at the cookbook or the setting reference.

## Features

- Easy configuration through premade [`Provider`](https://django-pyoidc.readthedocs.io/en/latest/user.html#providers) classes.
- Authenticate users from multiple providers
- Bearer authentication support for [django-rest-framework](https://www.django-rest-framework.org/) integration (**single provider**)
- Easy integration with the [Django permission system](https://django-pyoidc.readthedocs.io/en/latest/how-to.html#use-the-django-permission-system-with-oidc)
- Highly customizable design that should suit most needs
- Support back-channel logout
- Support service accounts (accounts for machine-to-machine uses)
- Sane and secure defaults settings

## Roadmap

- Frontchannel logout
- Switch to django signal system login/logout hooks
- Allow for audience check without customizing `get_user` using a setting

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
pip install django_pyoidc
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

Now you can pick an identity provider from the [available providers](https://django-pyoidc.readthedocs.io/en/latest/user.html#providers). Providers class are a quick way to generate the library configuration and URLs. You can also configure the settings manually, but this is not recommended if you are not familiar with the OpendID Connect (OIDC) protocol.

Add the following `DJANGO_PYOIDC` to your `settings.py` :

```python
# settings
DJANGO_PYOIDC = {
    # This is the name that your identity provider will have within the library
    "sso": {
        # change the following line to use your provider
        "provider_class": "django_pyoidc.providers.keycloak_18.Keycloak18Provider",
        
        # your secret should not be stored in settings.py, load them from an env variable
        "client_secret": os.getenv("SSO_CLIENT_SECRET"),
        "client_id": os.getenv("SSO_CLIENT_ID"),
        
        "provider_discovery_uri": "https://keycloak.example.com/auth/realms/fixme",
        
        # This setting allow the library to cache the provider configuration auto-detected using
        # the `provider_discovery_uri` setting
        "oidc_cache_provider_metadata": True,
    }
```

Finally, add OIDC views to your url configuration (`urls.py`):

```python
from django_pyoidc.helper import OIDCHelper

# `op_name` must be the name of your identity provider as used in the `DJANGO_PYOIDC` setting
oidc_helper = OIDCHelper(op_name="sso")

urlpatterns = [
    path(
        "auth/",
        include((oidc_helper.get_urlpatterns(), "django_pyoidc"), namespace="auth"),
    ),
]
```

And you are ready to go !

If you struggle with those instructions, take a look at [the quickstart tutorial](https://django-pyoidc.readthedocs.io/en/latest/tutorial.html#requirements).

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
