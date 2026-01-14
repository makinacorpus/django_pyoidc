class DjangoOIDCException(Exception):
    pass


class InvalidSIDException(DjangoOIDCException):
    pass


class TokenError(DjangoOIDCException):
    pass


class ExpiredToken(DjangoOIDCException):
    pass


class ClaimNotFoundError(DjangoOIDCException):
    pass


class InvalidOIDCConfigurationException(DjangoOIDCException):
    pass
