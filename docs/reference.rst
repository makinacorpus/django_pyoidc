
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

Each provider implements the configuration logic and should be used using the :ref:`provider-class-setting` setting.

.. tip::

    All the named arguments of __init__() can be set by configuring a setting **with the same**.

Provider list
^^^^^^^^^^^^^

.. autoclass:: django_pyoidc.providers.KeycloakProvider
    :members:
    :undoc-members:
    :special-members: __init__


.. autoclass:: django_pyoidc.providers.Keycloak18Provider
    :members:
    :undoc-members:
    :special-members: __init__


.. autoclass:: django_pyoidc.providers.Keycloak17Provider
    :members:
    :undoc-members:
    :special-members: __init__


.. autoclass:: django_pyoidc.providers.Keycloak10Provider
    :members:
    :undoc-members:
    :special-members: __init__


.. autoclass:: django_pyoidc.providers.LemonLDAPngProvider
    :members:
    :undoc-members:
    :special-members: __init__


.. autoclass:: django_pyoidc.providers.LemonLDAPng2Provider
    :members:
    :undoc-members:
    :special-members: __init__

.. automodule:: django_pyoidc.providers.Provider
    :members:
    :undoc-members:
    :special-members: __init__
