Makina Django OIDC Tutorials
============================

Getting started
---------------

Installation
~~~~~~~~~~~~

To install this library the easiest way is to use the pypi package

::

  pip install makina-django-oidc

Configuring your SSO
~~~~~~~~~~~~~~~~~~~~

Next, you should configure a client in your identity provider configuration interface.

.. warning::
    Incorrect configuration of your Identity Provider can create security issues. Please make sure you understand the values you input and their impact on the security level of your system.

We provide instruction for `Keycloak <https://www.keycloak.org/>`_ (version 18 and more), a free and open source Identity Provider maintened by Red Hat.

Keycloak
********

Start by connecting as your realm admin on the administration interface.



We will create a new client which supports the 'Authorization Code Flow'. Go to the client list of your realm and click on *"Create client"*

.. image:: images/keycloak/keycloak_create_client.png
    :alt: Screenshot of the client list from a Keycloak instance

Set the ``Client type`` to *OpenID Connect* and choose a meaningful ``Client ID``. The other options do not matter for this tutorial.

.. image:: images/keycloak/keycloak_create_client_p1.png
    :alt: Screenshot of the first page of a client configuration form from Keycloak

On the second page, enable ``Client authentication`` and the ``Standard Flow`` (also named *Authorization Code Flow* which is the one that we want).

.. image:: images/keycloak/keycloak_create_client_p2.png
    :alt: Screenshot of the second page of a client configuration form from Keycloak

Click on save and your client should be visible in the client list.

You can now configure your URLs. In the following example, the Django application is hosted at app.local:8082.

We configure our client URLs as such :

* ``Root URL`` and ``Home URL`` redirects to the root of our application *http://app.local:8082*
* With ``Valid redirect URIs`` we allow the user to be redirected to our application, or the one listening on ``localhost:9091`` and ``127.0.0.1:9091`` (for debug purposes)
* With ``Valid post logout redirect URIs`` the user can be redirected to our application after logout : *http://app.local:8082/**
* ``Web origins`` is set to *+* which allows (through CORS) all origins from the redirect URIs


.. image:: images/keycloak/keycloak_configure_urls.png
    :alt: Screenshot of url configuration page for Keycloak client

Take note of your ``Client ID`` and visit the *Credentials Page* to find your ``Client Secret``. You will need both to configure the OIDC connector.

.. image:: images/keycloak/keycloak_client_secret.png
    :alt: Screenshot of the Credentials page from a test client

Congratulation, your Keycloak configuration is complete ! 🎉

Other Identity provider
***********************


Configuring your Django project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install the application
***********************

It is now time to configure your Django project.


First, add the library app (``makina-django-oidc``) to your django applications, after `django.contrib.sessions` and `django.contrib.auth` :

.. code-block:: python
    :caption: settings.py

    INSTALLED_APPS = [
        "django.contrib.auth",
        "django.contrib.sessions",
        ...
        "makina-django-oidc"
    ]

Configure the library
*********************

.. note::
    In this part we use :ref:`providers <Providers>` as a quick way to generate the library configuration and URL patterns. However you can also :ref:`configure the settings <Django settings>` manually if you wish to dig into the configuration.

First, create a file named ``oidc.py`` and instantiate a :py:class:`makina_django_oidc.providers.Keyloack20Provider` as this is the provider that should be used with Keycloak.

Now you can pick an identity provider from the [available providers](). Providers class are a quick way to generate

Create a file named `oidc.py` next to your settings file and initialize your provider there.

We have many settings to provide :

* ``op_name`` is the name that this library associate internally with your provider.
* ``logout_redirect`` the default uri that will be used to redirect the user on logout
* ``failure_redirect`` the default uri where the user is redirected on login failure
* ``success_redirect`` the default uri where the user is redirected on login success
* ``redirect_requires_https`` the login view allows the user to be redirected to a dynamic URI. This setting enforce HTTPS on this uri.
* ``client_secret`` the client secret that you got from your identity provider
* ``client_id`` the client id that you got from your identity provider
* ``keycloak_realm_uri`` is the URI of your keycloak instance
* ``keycloak_realm`` is the name of your keycloak realm

Here is my configuration for this tutorial :

.. code-block:: python
    :caption: oidc.py

    from makina_django_oidc.providers.keycloak_20 import Keycloak20Provider

    my_project_provider = Keycloak20Provider(
        op_name="keycloak",
        logout_redirect="http://app.local:8082/",
        failure_redirect="http://app.local:8082/",
        success_redirect="http://app.local:8082/",
        redirect_requires_https=False,
        client_secret="s3cret",
        client_id="demo_makina_django_oidc",
        keycloak_realm_uri="http://keycloak.local:8080/",
        keycloak_realm="Demo",
    )


Then you can use the methods :py:meth:`get_config() <makina_django_oidc.providers.base.Provider.get_config>` and :py:meth:`get_urlpatterns() <makina_django_oidc.providers.base.Provider.get_urlpatterns>` to easily generate the settings and url configuration for your provider.

Edit you django configuration to add your configuration to ``MAKINA_DJANGO_OIDC`` settings :

.. code-block:: python
    :caption: settings.py

    from .oidc import my_project_provider

    MAKINA_DJANGO_OIDC = {
        **my_project_provider.get_config(allowed_hosts=["app.local:8082"]),
    }



Generate the URLs
*****************

Finally, add OIDC views to your url configuration (`urls.py`):

.. code-block:: python
    :caption: urls.py

    from .oidc import my_project_provider

    urlpatterns = [
        path("auth", include(my_project_provider.get_urlpatterns())),
    ]


This will include 4 views in your URL configuration. They all have a name that derives from the ``op_name`` that you used to create your provider.

* a :class:`login view <makina_django_oidc.views.OIDCLoginView>` named ``<op_name>-login``
* a :class:`logout view <makina_django_oidc.views.OIDCLogoutView>` named ``<op_name>-logout``
* a :class:`callback view <makina_django_oidc.views.OIDCCallbackView>` named ``<op_name>-callback``
* a :class:`backchannel logout view <makina_django_oidc.views.OIDCBackChannelLogoutView>` named ``<op_name>-backchannel-logout``

You should now be able to use the view names from this library to redirect the user to a login/logout page.
