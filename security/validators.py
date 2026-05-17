def validate_message(message):

    if not isinstance(message, str):
        return False

    if not message.strip():
        return False

    if len(message) > 1024:
        return False

    return True


if __name__ == "__main__":

    test_message = "Secure Message"

    result = validate_message(test_message)

    print("Message Valid:", result)
