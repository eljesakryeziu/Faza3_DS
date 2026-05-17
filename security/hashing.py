import hashlib

from security.audit import log_security_event
from security.exceptions import ValidationError, SecurityError


def generate_hash(data: str) -> str:
    """
    Generates a SHA-256 hash for the given string data.
    """

    if not isinstance(data, str):
        log_security_event(
            "HASH_ERROR", "Hash generation failed because data is not a string."
        )
        raise ValidationError("Data must be a string.")

    if not data.strip():
        log_security_event(
            "HASH_ERROR", "Hash generation failed because data is empty."
        )
        raise ValidationError("Data cannot be empty.")

    try:
        hashed_data = hashlib.sha256(data.encode("utf-8")).hexdigest()
        log_security_event("HASH_CREATED", "SHA-256 hash generated successfully.")
        return hashed_data

    except Exception as error:
        log_security_event("HASH_ERROR", f"Unexpected hashing error: {error}")
        raise SecurityError("Hash generation failed.") from error


if __name__ == "__main__":
    message = "Hello Secure World"

    try:
        hashed_message = generate_hash(message)

        print("Original Message:", message)
        print("SHA-256 Hash:", hashed_message)

    except SecurityError as error:
        print("Security error:", error)
