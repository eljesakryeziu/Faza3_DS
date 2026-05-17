import hashlib


def generate_hash(data):

    if not isinstance(data, str):
        raise TypeError("Data must be a string.")

    return hashlib.sha256(data.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    message = "Hello Secure World"

    hashed_message = generate_hash(message)

    print("Original Message:", message)
    print("SHA-256 Hash:", hashed_message)
