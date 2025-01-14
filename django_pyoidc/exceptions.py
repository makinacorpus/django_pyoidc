class InvalidSIDException(Exception):
    pass


class TokenError(Exception):
    pass


class ExpiredToken(Exception):
    pass


class ClaimNotFoundError(Exception):
    pass


class InvalidOIDCConfigurationException(Exception):
    pass
