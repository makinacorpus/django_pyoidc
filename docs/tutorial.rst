Makina Django OIDC Tutorials
============================

Getting started
---------------

Installation
~~~~~~~~~~~~

To install this library the easiest way is to use the pypi package

::

  pip install django-pyoidc

Configuring your SSO
~~~~~~~~~~~~~~~~~~~~

Next, you should configure a client in your identity provider configuration interface.

.. warning::
    Incorrect configuration of your Identity Provider can create security issues. Please make sure you understand the values you input
    and their impact on the security level of your system.

We provide instructions for `Keycloak <https://www.keycloak.org/>`_ (version 18 and more), a free and open source Identity Provider maintened by Red Hat.

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

TODO: using a 2nd app at localhost:9091 is confusing, remove that, use a localhost:something, better

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


First, add the library app (``django-pyoidc``) to your django applications, after `django.contrib.sessions` and `django.contrib.auth` :

.. code-block:: python
    :caption: settings.py

    INSTALLED_APPS = [
        "django.contrib.auth",
        "django.contrib.sessions",
        ...
        "django-pyoidc"
    ]

.. warning::
    Do not forget later to run the **migrations** ! This module requires some extra database storage tables.

Configure a cache backend
*************************

**You must have a cache backend** for this library to work ! The OIDC protocol is very statefull and we use Django cache system to store data.
If you want to understand why, you can read the :ref:`Cache Management` page.

For the sake of this tutorial, you can use this cache management snippet (it should be pasted in your ``settings.py``) :

.. code-block:: python

    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "unique-snowflake",
        }
    }

.. warning::
    Do not use those settings in production ! Go read the `django documentation <https://docs.djangoproject.com/en/stable/topics/cache/#setting-up-the-cache>`_ for more details.

Configure the library
*********************

.. note::
    In this part we use :ref:`providers <Providers>` as a quick way to generate the library configuration and URL patterns.
    However you can also :ref:`configure the settings <Django settings>` manually if you wish to dig into the configuration.

First, create a file named ``oidc.py`` and instantiate a :py:class:`django_pyoidc.providers.Keyloack20Provider`
as this is the provider that should be used with Keycloak.

We have many settings to provide :

* ``op_name`` is the name that this library associate internally with your provider.
* ``client_id`` the client id that you got from your identity provider
* ``client_secret`` the client secret that you got from your identity provider
* ``keycloak_base_uri`` is the URI of your keycloak instance
* ``keycloak_realm`` is the name of your keycloak realm

Some extra settings are also available :

* ``success_redirect`` the default uri where the user is redirected on login success
* ``failure_redirect`` the default uri where the user is redirected on login failure
* ``logout_redirect`` the default uri that will be used to redirect the user on logo
* ``redirect_requires_https`` the login view allows the user to be redirected to a dynamic URI. This setting enforce HTTPS on this uri.

TODO: provide good defaults for these settings

Here is my configuration for this tutorial :

.. code-block:: python
    :caption: oidc.py

    from django_pyoidc.providers.keycloak import KeycloakProvider

    my_oidc_provider = KeycloakProvider(
        op_name="keycloak",
        client_secret="s3cret",
        client_id="demo_django_pyoidc",
        keycloak_base_uri="http://keycloak.local:8080/auth/",
        keycloak_realm="Demo",
        #logout_redirect="http://app.local:8082/",
        #failure_redirect="http://app.local:8082/",
        success_redirect="http://app.local:8082/user",
        redirect_requires_https=False, # useful in dev
    )

**Note**: after Keycloak 17 the ``auth/`` prefix is removed by default on Keycloak base paths.
Here we use a Keycloak where the ``KC_HTTP_RELATIVE_PATH=/auth`` setting was set, to maintain compatibility
with an older version. If you did not use that setting in your Keycloak instance the ``keycloak_base_uri``
parameter would simply be "http://keycloak.local:8080/".

.. tip:

You may have the auto-configuration json link provided, for our example this url is http://keycloak.local:8080/auth/realms/Demo/.well-known/openid-configuration
If you check this json you can extract paths from this file. For example the first information is :
``http://keycloak.local:8080/auth/realms/Demo``. Everything before the ``realms`` keyword is the
``keycloak_base_uri`` that this library needs, the word following ``realms/`` is the ``keycloak_realm`` parameter.

FIXME  Then you can use the methods :py:meth:`get_config() <django_pyoidc.providers.base.Provider.get_config>` and
:py:meth:`get_urlpatterns() <django_pyoidc.providers.base.Provider.get_urlpatterns>` to easily generate the settings
and url configuration for your provider.

Edit your django configuration to add your configuration to ``DJANGO_PYOIDC`` settings :

.. code-block:: python
    :caption: settings.py

    from .oidc import my_oidc_provider

    DJANGO_PYOIDC = {
        FIXME **my_oidc_provider.get_config(login_uris_redirect_allowed_hosts=["app.local:8082"]),
    }

TODO: remove login_uris_redirect_allowed_hosts from this step, should be in settings

Generate the URLs
*****************

Finally, add OIDC views to your url configuration (`urls.py`):

.. code-block:: python
    :caption: urls.py

    from .oidc import my_oidc_provider

    urlpatterns = [
        path("auth", include(my_oidc_provider.get_urlpatterns())),
    ]

This will include 4 views in your URL configuration. They all have a name that derives from the ``op_name`` that you used to create your provider.

* a :class:`login view <django_pyoidc.views.OIDCLoginView>` named ``<op_name>-login``, here handled on the ``/auth/login`` path
* a :class:`logout view <django_pyoidc.views.OIDCLogoutView>` named ``<op_name>-logout``, here handled on the ``/auth/logout`` path
* a :class:`callback view <django_pyoidc.views.OIDCCallbackView>` named ``<op_name>-callback``, here handled on the ``/auth/callback`` path
* a :class:`backchannel logout view <django_pyoidc.views.OIDCBackChannelLogoutView>` named ``<op_name>-backchannel-logout``, here handled on the ``/auth/backchannel-logout`` path

You should now be able to use the view names from this library to redirect the user to a login/logout page.
