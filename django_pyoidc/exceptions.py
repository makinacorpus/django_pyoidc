class DjangoOIDCException(Exception):  # noqa: N818
    pass


class InvalidSIDException(DjangoOIDCException):
    pass


class TokenError(DjangoOIDCException):
    pass


class ExpiredToken(DjangoOIDCException):
    pass


class FailedIntrospection(DjangoOIDCException):
    pass


class ClaimNotFoundError(DjangoOIDCException):
    pass


class InvalidOIDCConfigurationException(DjangoOIDCException):
    pass
