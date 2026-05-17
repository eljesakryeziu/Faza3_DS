from security.audit import log_failed_validation, log_security_event

from security.exceptions import ValidationError

MAX_MESSAGE_LENGTH = 1024


def validate_message(message: str) -> bool:
    """
    Validates client messages before processing.
    """

    if not isinstance(message, str):
        log_failed_validation(message)
        raise ValidationError("Message must be a string.")

    if not message.strip():
        log_failed_validation(message)
        raise ValidationError("Message cannot be empty.")

    if len(message) > MAX_MESSAGE_LENGTH:
        log_failed_validation(message)
        raise ValidationError(f"Message exceeds {MAX_MESSAGE_LENGTH} characters.")

    log_security_event("VALIDATION_SUCCESS", "Message validated successfully.")

    return True


if __name__ == "__main__":

    test_message = "Secure Message"

    try:
        result = validate_message(test_message)

        print("Message Valid:", result)

    except Exception as error:
        print("Validation Error:", error)
