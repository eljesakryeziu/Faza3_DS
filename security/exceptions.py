class SecurityError(Exception):
    """
    Base class for security-related exceptions.
    """

    pass


class InvalidSignatureError(SecurityError):
    """
    Raised when a digital signature verification fails.
    """

    pass


class IntegrityCheckError(SecurityError):
    """
    Raised when message integrity verification fails.
    """

    pass


class ValidationError(SecurityError):
    """
    Raised when invalid input is detected.
    """

    pass


class AuthenticationError(SecurityError):
    """
    Raised when authentication fails.
    """

    pass


class EncryptionError(SecurityError):
    """
    Raised when encryption or decryption fails.
    """

    pass
