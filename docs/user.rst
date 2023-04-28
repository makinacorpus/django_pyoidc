User API Reference
==================

Django settings
---------------


URI_FAILURE
***********

This setting configures where a user is redirected on login failure.

URI_LOGOUT
**********

This setting configures where a user is redirected on logout.

URI_DEFAULT_SUCCESS
*******************

This setting configures the default redirection URI on login success

URI_PROVIDER
************

This setting configures your provider root URI. **TODO** : rename to PROVIDER_HOST or something like that.

URI_CONFIG
**********

This settings configures the path to your OIDC configuration. **TODO : example**.

CALLBACK_PATH
*************

This setting is used to reference the callback view that should be provided as the ``redirect_uri`` parameter of the *Authorization Code Flow*.

REDIRECT_REQUIRES_HTTPS
***********************

This setting configures if dynamic login redirection URI must have the ``https`` scheme.

REDIRECT_ALLOWED_HOSTS
**********************

This setting configures the list of allowed host in dynamic URI redirections.

CLIENT_SECRET
*************

This setting configures the client secret used to authentify your application with an identity provider.

CLIENT_ID
*********

This setting configures the client id used to authentify your application with an identity provider.

CACHE_BACKEND
*************

This setting configures the cache backend that is used to store sessions details.
You can read more about *Cache Management* :ref:`here <Cache Management>`.

Views
-----

.. note::
    When instantiating a view from this library (ie through django's 'as_view()') you **must** set the named argument ``op_name`` to point to a valid ``MAKINA_DJANGO_OIDC`` settings entry.
    If you use :ref:`Providers` then this behaviour is automatically implemented.

    Here is an example :

    .. code-block:: python

        from .oidc_providers import my_project_provider

        urlpatterns = [
            path("auth/callback", OIDCCallbackView.as_view(op_name="keycloak"),),
        ]



.. autoclass:: makina_django_oidc.views.OIDCLoginView
    :members:
    :special-members: http_method_names

.. autoclass:: makina_django_oidc.views.OIDCCallbackView
    :members:

.. autoclass:: makina_django_oidc.views.OIDCLogoutView
    :members:

.. autoclass:: makina_django_oidc.views.OIDCBackChannelLogoutView
    :members:




Providers
---------

Providers classes allows the final user to configure their project without having to understand how to map their Identity Provider configuration settings to this library settings.

Each provider implements the configuration logic and provides mostly two methods :


* One to generate a configuration dict to be inserted in the ``MAKINA_DJANGO_OIDC`` value of your django settings : :py:meth:`get_config() <makina_django_oidc.providers.base.Provider.get_config>`
* One to generate urls to be :func:`included <django:django.urls.reverse>` in your url configuration : :py:meth:`get_urlpatterns() <makina_django_oidc.providers.base.Provider.get_urlpatterns>`

.. autoclass:: makina_django_oidc.providers.Keycloak20Provider
    :members:
    :undoc-members:
    :special-members: __init__