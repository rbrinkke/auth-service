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

class InvalidScopesError(AuthenticationError):
    """Requested scope is invalid."""
    pass

class EmailAlreadyExistsError(Exception):
    """Email is already registered."""
    pass

class UserNotFoundError(Exception):
    """User not found."""
    pass

class InvalidVerificationCodeError(Exception):
    """Verification code is invalid or expired."""
    pass

class OrganizationNotFoundError(Exception):
    """Organization not found."""
    pass

class MembershipNotFoundError(Exception):
    """User is not a member of the organization."""
    pass
