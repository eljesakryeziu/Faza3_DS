from security.hashing import generate_hash
from security.audit import log_security_event, log_signature_failure
from security.exceptions import InvalidSignatureError, ValidationError


def create_signature(message: str) -> str:
    """
    Creates a digital signature using SHA-256 hashing.
    """

    if not message or not isinstance(message, str):
        log_security_event(
            "SIGNATURE_ERROR", "Failed to create signature due to invalid message."
        )
        raise ValidationError("Message must be a non-empty string.")

    signature = generate_hash(message)

    log_security_event("SIGNATURE_CREATED", "Digital signature created successfully.")

    return signature


def verify_signature(message: str, signature: str) -> bool:
    """
    Verifies the digital signature of a message.
    """

    if not message or not signature:
        log_security_event(
            "SIGNATURE_ERROR", "Signature verification failed due to missing data."
        )
        raise ValidationError("Message and signature cannot be empty.")

    expected_signature = generate_hash(message)

    if expected_signature != signature:
        log_signature_failure("Unknown Client")

        raise InvalidSignatureError("Digital signature verification failed.")

    log_security_event("SIGNATURE_VERIFIED", "Digital signature verified successfully.")

    return True


if __name__ == "__main__":

    message = "Secure Message"

    try:
        signature = create_signature(message)

        print("Signature:", signature)

        is_valid = verify_signature(message, signature)

        print("Signature Valid:", is_valid)

    except Exception as error:
        print("Error:", error)
