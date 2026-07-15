NEXT
----
- drop support for python 3.8
- drop support for python 3.9
- fix LoginRequiredMiddleware was unusable with django pyoidc (#78)

1.0.12
------
- improve error message when we fail to introspect a token (#73)

1.0.11
------
- run unit test against django master branch (https://www.djangoproject.com/weblog/2025/apr/17/run-your-tests-against-django-main/)

1.0.10
------
- fix readme installation instructions #65 (thank you rmattes !)

1.0.9
-----
- drf : improve missing introspection endpoint error handling
- have all `django_pyoidc` exceptions inherit from `DjangoOIDCException`
- improve documentation for drf integration : `use_introspection_on_access_tokens` and `hook_validate_access_token`
- add `hook_session_logout` setting #54 to allow the configuration of backchannel logout behaviour

1.0.8
-----
- add 'scopes' settings, see issue #31

1.0.7
-----
- remove pypi django 3.2/4.0/4.1 classifier

1.0.6
-----
- fix project name in sphinx metadata
- fix missing django 5.2 and python 3.13 classifiers in pyproject.toml

1.0.4
-----
- switch jwt library to pyjwt


1.0.3
-----
- fix drf spectacular schema generation

1.0.0
----

First release !
