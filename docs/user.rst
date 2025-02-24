User API Reference
==================

Django settings
---------------


.. note::
    We provide a set of predefined settings for some identity providers. As such, you can avoid having to configure by yourself this library and it's views.
    Take a look at the :ref:`tutorial <Configure the library>` !


Providers settings
~~~~~~~~~~~~~~~~~~

All those settings must be defined in ``settings.py`` under the variable name ``DJANGO_PYOIDC``.
You should define them as a nested dictionary. The key to this dictionary is called your **provider name** (or **op_name** in some places). All your settings configuration are local to this provider. This allows multi-provider configurations.

.. code-block:: python

    DJANGO_PYOIDC = {
        'my_provider_name' : {
            'setting_1' : 'value',
            'setting_2' : 'value'
        }
    }

post_login_uri_failure
***********

This setting configures where a user is redirected on login failure, defaults to Django base url.

post_login_uri_success
*******************

This setting configures the default redirection URI on login success, defaults to Django base url.


post_logout_redirect_uri
**********

This setting configures where a user is redirected after successful SSO logout, defaults to Django base url.

URI_PROVIDER
************

This setting configures your provider root URI. **TODO** : rename to PROVIDER_HOST or something like that.

URI_CONFIG
**********

This settings configures the path to your OIDC configuration. **TODO : example**.

oidc_callback_path
*************

This setting is used to reference the callback view that should be provided as the ``redirect_uri`` parameter of the *Authorization Code Flow*.

login_redirection_requires_https
***********************

This setting configures if dynamic login redirection URI must have the ``https`` scheme.

login_uris_redirect_allowed_hosts
**********************

This setting configures the list of allowed host in dynamic URI redirections.

client_secret
*************

This setting configures the client secret used to authentify your application with an identity provider.

client_id
*********

This setting configures the client id used to authentify your application with an identity provider.

cache_django_backend
*************

This setting configures the cache backend that is used to store OIDC sessions details.
You can read more about *Cache Management* :ref:`here <Cache Management>`.

Hook settings
~~~~~~~~~~~~~

Hook settings are path to a python function that should be called in specific context. We use a custom syntax to reference a function of a module.

The syntax is : ``<module path>:<function name>``.


So for example, if you were to have a module named ``oidc.py`` next to your project settings with a function called ``logout_callback`` you should use the string ``<your application root module>.oidc:logout_callback`` in your settings.

.. note::
    Hook settings work on a provider by provider basis, you can have different hook functions for each of your identity providers


.. note::
    All those settings are optional

HOOK_USER_LOGOUT
***************

Calls the provided function on user logout. The function is called if the logout is successful, but before redirecting the user.

This function takes two arguments :

1. a request instance :class:`django:django.http.HttpRequest`
2. TODO FIXME RLE

If the user was logged in, you can get the user using ``request.user``.

HOOK_USER_LOGIN
**************

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

Views
-----

.. note::
    When instantiating a view from this library (ie through django's 'as_view()') you **must** set the named argument ``op_name`` to point to a valid ``DJANGO_PYOIDC`` settings entry.
    If you use :ref:`Providers` then this behaviour is automatically implemented.

    Here is an example :

    .. code-block:: python

        from .oidc_providers import my_project_provider

        urlpatterns = [
            path("auth/callback", OIDCCallbackView.as_view(op_name="keycloak"),),
        ]



.. autoclass:: django_pyoidc.views.OIDCLoginView
    :members:
    :special-members: http_method_names

.. autoclass:: django_pyoidc.views.OIDCCallbackView
    :members:

.. autoclass:: django_pyoidc.views.OIDCLogoutView
    :members:

.. autoclass:: django_pyoidc.views.OIDCBackChannelLogoutView
    :members:




Providers
---------

Providers classes allows the final user to configure their project without having to understand how to map their Identity Provider configuration settings to this library settings.

Each provider implements the configuration logic and provides mostly two methods :


* One to generate a configuration dict to be inserted in the ``DJANGO_PYOIDC`` value of your django settings FIXME  : :py:meth:`get_config() <django_pyoidc.providers.base.Provider.get_config>`
* One to generate urls to be :func:`included <django:django.urls.reverse>` in your url configuration : :py:meth:`get_urlpatterns() <django_pyoidc.providers.base.Provider.get_urlpatterns>`

.. autoclass:: django_pyoidc.providers.KeycloakProvider
    :members:
    :undoc-members:
    :special-members: __init__



.. automodule:: django_pyoidc.providers.base
    :members:
    :undoc-members:
    :special-members: __init__