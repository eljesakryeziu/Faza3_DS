from security.hashing import generate_hash


def verify_integrity(original_hash, recieved_message):

    new_hash = generate_hash(recieved_message)

    return original_hash == new_hash


if __name__ == "__main__":

    message = "Hello Secure World"

    original_hash = generate_hash(message)

    print("Original Hash:", original_hash)

    is_valid = verify_integrity(original_hash, message)

    print("Integrity Verified:", is_valid)
