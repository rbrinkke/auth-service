class AuthenticationError(Exception):
    """Base authentication error."""
    pass

class InvalidCredentialsError(AuthenticationError):
    """Invalid email or password."""
    pass

class MFARequiredError(AuthenticationError):
    """MFA verification required."""
    pass

class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    pass

class InvalidTokenError(AuthenticationError):
    """Token is invalid."""
    pass

class AccountLockedError(AuthenticationError):
    """Account is locked."""
    pass
