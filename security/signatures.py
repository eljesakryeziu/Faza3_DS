from security.hashing import generate_hash


def create_signature(message):

    return generate_hash(message)


def verify_signature(message, signature):

    expected_signature = generate_hash(message)

    return expected_signature == signature


if __name__ == "__main__":

    message = "Secure Message"

    signature = create_signature(message)

    print("Signature:", signature)

    is_valid = verify_signature(message, signature)

    print("Signature Valid:", is_valid)
