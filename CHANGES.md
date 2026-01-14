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
