from security.hashing import generate_hash
from security.audit import log_security_event
from security.exceptions import IntegrityCheckError, ValidationError


def verify_integrity(original_hash: str, received_message: str) -> bool:
    """
    Verifies message integrity using SHA-256 hashing.
    """

    if not original_hash or not received_message:
        log_security_event(
            "INTEGRITY_ERROR", "Integrity verification failed due to missing data."
        )
        raise ValidationError("Hash and message cannot be empty.")

    new_hash = generate_hash(received_message)

    if original_hash != new_hash:
        log_security_event("INTEGRITY_FAILED", "Message integrity verification failed.")
        raise IntegrityCheckError("Message integrity check failed.")

    log_security_event("INTEGRITY_SUCCESS", "Message integrity verified successfully.")

    return True


if __name__ == "__main__":

    message = "Hello Secure World"

    original_hash = generate_hash(message)

    print("Original Hash:", original_hash)

    try:
        is_valid = verify_integrity(original_hash, message)

        print("Integrity Verified:", is_valid)

    except Exception as error:
        print("Error:", error)
