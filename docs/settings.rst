About settings
==============

.. tip::

    We provide a way to autoconfigure many settings using your identity provider autoconfiguration endpoints.


.. tip::
    We provide ``Provider`` classes which implement setting generation for some popular identity providers (Keycloak, etc.).


All those settings must be defined in ``settings.py`` under the variable name ``DJANGO_PYOIDC``.
You should define them as a nested dictionary. The key to this dictionary is called your **provider name** (or **op_name** in some places). All your settings configuration are local to this provider. This allows multi-provider configurations.

.. important::

    Manually defined settings replaces settings from providers.

Identity provider configuration
===============================

.. _provider-class-setting:

provider_class
**************

**Default** : "django_pyoidc.providers.Provider"

Use this setting to plug in a provider class that will be used to generate the settings of your identity provider.
Some providers expect to receives custom arguments : you should defines them as settings.

For example, the ``Keycloak10Provider`` can use two arguments : ``keycloak_base_uri`` and ``keycloak_realm``. If you wish to use them, define them in ``DJANGO_PYOIDC`` as your identity provider setting.

provider_discovery_uri
**********************

This settings should be the URL of an OIDC autoconfiguration endpoint. We will use this
setting to discover and store all the URLs needed to perform user authentication.


.. note::
    The ``.well-known/openid-configuration`` part of this url is not necessary, it will automatically be added.

client_secret
*************

This setting configures the client secret used to authenticate your application with an identity provider.

.. note::
    If you only have a client_id and not client_secret it means your OIDC client (application) was defined as a public application, which is normally only done for javascript SLA applications. A regular web application should have a client_secret, and an API backend application too.


client_id
*********

This setting configures the client id used to authenticate your application with an identity provider.

use_introspection_on_access_tokens
**********************************

**Default** : ``True``

This setting is enabled by default on Django Rest Framework authentication (when you use drf for the key in DJANGO_PYOIDC, see :ref:`Configuring django_rest_framework` for more details). You can also activate it for more classical providers. But in DRF mode the ``access_token`` is the only information you receive from the user, and you need to extract claims from the token, that's why we use introspection to both validate the token and get more informations from it.

When this setting is enabled, we will use the *introspection endpoint* of the
identity provider to perform token validation and return a clear extraction of the ``access_token``.

When disabled the access token claims are not extracted, you only have the ``access_token`` in its JWT encoded format. You can then decide to try an extraction on your own with a jwt library, or keep it as a JWT. If your SSO provider provides enough claims in the userinfo token you do not need to extract content from the ``access_token``. That's why we do not extract the ``access_token`` claims by default. If you need informations from the ``access_token`` activating this setting will add a round trip to the SSO server, but at the end you'll have all the ``access_tokens`` claims in clear text.

oidc_paths_prefix
*****************

**Default** : dynamically computed using the name of your identity provide

You can use this setting to change how the OIDC views are named. By default they are named ``<op_name>_[login|callback]``.

Configuring this setting allows you to swap ``<op_name`` with an other value.

Advanced identity provider configuration
========================================

oidc_logout_query_string_redirect_parameter
*******************************************

**Todo**

oidc_logout_query_string_extra_parameters_dict
**********************************************

**Default** : ``{}``

All the key/values of this dictionary are used as http query params when performing a logout request
to the identity provider.

client_authn_method
*******************

**Default** : see ``oic/utils/authn/client.py:437``

Methods that the OIDC client can use to authenticate itself. It's a dictionary with method names as
keys and method classes as values.

Login/Logout redirections
=========================

post_login_uri_failure
**********************

This setting configures where a user is redirected on login failure, defaults to Django base url.

post_login_uri_success
**********************

This setting configures the default redirection URI on login success, defaults to Django base url.

post_logout_redirect_uri
************************

This setting configures where a user is redirected after successful SSO logout, defaults to Django base url.

oidc_callback_path
******************

**Default** : <op_name

This setting is used to reference the callback view that should be provided as the ``redirect_uri`` parameter of the *Authorization Code Flow*.

login_redirection_requires_https
***********************

This setting configures if dynamic login redirection URI must have the ``https`` scheme.

login_uris_redirect_allowed_hosts
**********************

This setting configures the list of allowed host in dynamic URI redirections.

Cache
=====

oidc_cache_provider_metadata
****************************

**Default** : ``False``

When this setting is enabled, we will cache the calls to the autoconfiguration endpoint of the OIDC
identity provider.

oidc_cache_provider_metadata_ttl
********************************

**Default** : ``120``


This settings has no effect if ``oidc_cache_provider_metadata`` is disabled.

Otherwise, it configures the lifetime (in seconds) of cached response for the autoconfiguration of
the identity provider.

cache_django_backend
********************

This setting configures the cache backend that is used to store OIDC sessions details. It should be
the name of a cache defined in the ``CACHES` django settings.
You can read more about *Cache Management* :ref:`here <Cache Management>`.

Hook
====

Hook settings are path to a python function that should be called in specific context. We use a custom syntax to reference a function of a module.

The syntax is : ``<module path>:<function name>``.


So for example, if you were to have a module named ``oidc.py`` next to your project settings with a function called ``logout_callback`` you should use the string ``<your application root module>.oidc:logout_callback`` in your settings.

.. note::
    Hook settings work on a provider by provider basis, you can have different hook functions for each of your identity providers


.. note::
    All those settings are optional

hook_user_logout
****************

Calls the provided function on user logout. The function is called if the logout is successful, but before redirecting the user.

This function takes two arguments :

1. a request instance :class:`django:django.http.HttpRequest`
2. the request args sent to the sso server (missing the id_token_hint element)

If the user was logged in, you can get the user using ``request.user``.

hook_user_login
****************

Calls the provided function on user login. The functions is called if the login is successful.

This function takes two arguments :

1. a request instance :class:`django:django.http.HttpRequest`
2. a user instance :class:`django.contrib.auth.models.User`

Since the user wasn't logged in, it is not yet attached to the request instance at this stage. As such trying to access ``request.user`` will return an unauthenticated user.

hook_get_user
*************

Calls the provided function on user login. It takes two arguments :

* the user info token (a dictionary) from the identity provider
* the id token

It is expected to return a :class:`django.contrib.auth.models.User` instance.
