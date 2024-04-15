This section of tests is about end to end (e2e) tests.

We launch a local keycloak or lemonldap SSO server using docker. We set some configurations in this SSO, and then we test connecting the Django test instance to this SSO server on various stuff (login, logout, audiences, etc.).
