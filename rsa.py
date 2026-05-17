
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Union


DEFAULT_KEY_SIZE = 2048
DEFAULT_PUBLIC_EXPONENT = 65537
DEFAULT_ENCODING = "utf-8"
SHA256_DIGEST_SIZE = 32
OAEP_SHA256_LABEL = b""
OAEP_2048_SHA256_MAX_MESSAGE_BYTES = 190

_RSA_ENCRYPTION_OID_DER = b"\x06\t*\x86H\x86\xf7\r\x01\x01\x01"
_PEM_PUBLIC_HEADER = "PUBLIC KEY"
_PEM_PRIVATE_HEADER = "PRIVATE KEY"

_SMALL_PRIMES = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
)


class RSAError(Exception):
    """Base class for RSA-related errors."""


class RSAKeyFormatError(RSAError):
    """Raised when a PEM/DER key cannot be parsed."""


class MessageTooLongError(RSAError):
    """Raised when plaintext exceeds the OAEP size limit."""


class RSAEncryptionError(RSAError):
    """Raised when encryption fails."""


class RSADecryptionError(RSAError):
    """Raised when decryption fails."""


class RSASignatureError(RSAError):
    """Raised when signing fails."""


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    def size_bits(self) -> int:
        return self.n.bit_length()

    def size_bytes(self) -> int:
        return (self.size_bits() + 7) // 8

    def max_oaep_message_length(self) -> int:
        return self.size_bytes() - (2 * SHA256_DIGEST_SIZE) - 2


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    def size_bits(self) -> int:
        return self.n.bit_length()

    def size_bytes(self) -> int:
        return (self.size_bits() + 7) // 8

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)


def generate_keypair(
    key_size: int = DEFAULT_KEY_SIZE,
    public_exponent: int = DEFAULT_PUBLIC_EXPONENT,
) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generate a new RSA keypair.

    Returns:
        (private_key, public_key)
    """
    if key_size < 1024:
        raise ValueError("key_size must be at least 1024 bits")
    if key_size % 256 != 0:
        raise ValueError("key_size must be a multiple of 256")
    if public_exponent < 3 or public_exponent % 2 == 0:
        raise ValueError("public_exponent must be an odd integer >= 3")

    half_bits = key_size // 2

    while True:
        p = _generate_prime(half_bits, public_exponent)
        q = _generate_prime(key_size - half_bits, public_exponent)
        if p == q:
            continue
        if p < q:
            p, q = q, p

        n = p * q
        if n.bit_length() != key_size:
            continue

        phi = (p - 1) * (q - 1)
        if phi % public_exponent == 0:
            continue

        d = pow(public_exponent, -1, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = pow(q, -1, p)

        private_key = RSAPrivateKey(
            n=n,
            e=public_exponent,
            d=d,
            p=p,
            q=q,
            dp=dp,
            dq=dq,
            qinv=qinv,
        )
        return private_key, private_key.public_key()


def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialize a public key to PEM (SubjectPublicKeyInfo)."""
    pkcs1_der = _der_sequence(
        _der_integer(public_key.n),
        _der_integer(public_key.e),
    )
    algorithm_identifier = _der_sequence(
        _RSA_ENCRYPTION_OID_DER,
        _der_null(),
    )
    spki_der = _der_sequence(
        algorithm_identifier,
        _der_bit_string(pkcs1_der),
    )
    return _pem_encode(_PEM_PUBLIC_HEADER, spki_der)


def serialize_private_key(private_key: RSAPrivateKey) -> bytes:
    """Serialize a private key to PEM (PKCS#8)."""
    pkcs1_der = _der_sequence(
        _der_integer(0),
        _der_integer(private_key.n),
        _der_integer(private_key.e),
        _der_integer(private_key.d),
        _der_integer(private_key.p),
        _der_integer(private_key.q),
        _der_integer(private_key.dp),
        _der_integer(private_key.dq),
        _der_integer(private_key.qinv),
    )
    algorithm_identifier = _der_sequence(
        _RSA_ENCRYPTION_OID_DER,
        _der_null(),
    )
    pkcs8_der = _der_sequence(
        _der_integer(0),
        algorithm_identifier,
        _der_octet_string(pkcs1_der),
    )
    return _pem_encode(_PEM_PRIVATE_HEADER, pkcs8_der)


def deserialize_public_key(pem_data: Union[str, bytes]) -> RSAPublicKey:
    """Load a public key from PEM (SubjectPublicKeyInfo)."""
    der = _pem_decode(pem_data, _PEM_PUBLIC_HEADER)
    root = _DERReader(der)
    root_sequence = _DERReader(root.read_tlv(0x30))

    algorithm_reader = _DERReader(root_sequence.read_tlv(0x30))
    oid = algorithm_reader.read_tlv(0x06)
    if oid != _RSA_ENCRYPTION_OID_DER[2:]:
        raise RSAKeyFormatError("Unsupported public key algorithm")
    _ = algorithm_reader.read_tlv(0x05)
    algorithm_reader.ensure_exhausted()

    bit_string = root_sequence.read_tlv(0x03)
    if not bit_string or bit_string[0] != 0:
        raise RSAKeyFormatError("Invalid public key BIT STRING")

    public_key_reader = _DERReader(bit_string[1:])
    public_key_sequence = _DERReader(public_key_reader.read_tlv(0x30))
    n = _decode_der_integer(public_key_sequence.read_tlv(0x02))
    e = _decode_der_integer(public_key_sequence.read_tlv(0x02))
    public_key_sequence.ensure_exhausted()
    public_key_reader.ensure_exhausted()
    root_sequence.ensure_exhausted()
    root.ensure_exhausted()
    return RSAPublicKey(n=n, e=e)


def deserialize_private_key(pem_data: Union[str, bytes]) -> RSAPrivateKey:
    """Load a private key from PEM (PKCS#8)."""
    der = _pem_decode(pem_data, _PEM_PRIVATE_HEADER)
    root = _DERReader(der)
    root_sequence = _DERReader(root.read_tlv(0x30))

    outer_version = _decode_der_integer(root_sequence.read_tlv(0x02))
    if outer_version != 0:
        raise RSAKeyFormatError("Unsupported PKCS#8 version")

    algorithm_reader = _DERReader(root_sequence.read_tlv(0x30))
    oid = algorithm_reader.read_tlv(0x06)
    if oid != _RSA_ENCRYPTION_OID_DER[2:]:
        raise RSAKeyFormatError("Unsupported private key algorithm")
    _ = algorithm_reader.read_tlv(0x05)
    algorithm_reader.ensure_exhausted()

    private_key_octets = root_sequence.read_tlv(0x04)
    pkcs1_reader = _DERReader(private_key_octets)
    pkcs1_sequence = _DERReader(pkcs1_reader.read_tlv(0x30))

    inner_version = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    if inner_version != 0:
        raise RSAKeyFormatError("Unsupported PKCS#1 version")

    n = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    e = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    d = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    p = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    q = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    dp = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    dq = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))
    qinv = _decode_der_integer(pkcs1_sequence.read_tlv(0x02))

    pkcs1_sequence.ensure_exhausted()
    pkcs1_reader.ensure_exhausted()
    root_sequence.ensure_exhausted()
    root.ensure_exhausted()

    return RSAPrivateKey(
        n=n,
        e=e,
        d=d,
        p=p,
        q=q,
        dp=dp,
        dq=dq,
        qinv=qinv,
    )


def save_public_key(public_key: RSAPublicKey, path: Union[str, Path]) -> Path:
    """Save a PEM public key to disk."""
    destination = Path(path)
    destination.write_bytes(serialize_public_key(public_key))
    return destination


def save_private_key(private_key: RSAPrivateKey, path: Union[str, Path]) -> Path:
    """Save a PEM private key to disk."""
    destination = Path(path)
    destination.write_bytes(serialize_private_key(private_key))
    return destination


def load_public_key(path: Union[str, Path]) -> RSAPublicKey:
    """Load a PEM public key from disk."""
    return deserialize_public_key(Path(path).read_bytes())


def load_private_key(path: Union[str, Path]) -> RSAPrivateKey:
    """Load a PEM private key from disk."""
    return deserialize_private_key(Path(path).read_bytes())


def encrypt_message(
    plaintext: Union[str, bytes],
    recipient_public_key: RSAPublicKey,
    label: bytes = OAEP_SHA256_LABEL,
    encoding: str = DEFAULT_ENCODING,
) -> bytes:
    """
    Encrypt plaintext with RSA-OAEP(SHA-256).

    Accepts either a UTF-8 string or raw bytes.
    Returns raw ciphertext bytes.
    """
    message = _ensure_bytes(plaintext, encoding)
    k = recipient_public_key.size_bytes()
    h_len = SHA256_DIGEST_SIZE
    max_length = recipient_public_key.max_oaep_message_length()

    if len(message) > max_length:
        raise MessageTooLongError(
            f"Plaintext is {len(message)} bytes, but the maximum allowed is "
            f"{max_length} bytes for this key size and OAEP/SHA-256."
        )

    l_hash = sha256_digest(label)
    ps = b"\x00" * (k - len(message) - (2 * h_len) - 2)
    db = l_hash + ps + b"\x01" + message
    seed = secrets.token_bytes(h_len)
    db_mask = mgf1(seed, k - h_len - 1)
    masked_db = _xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, h_len)
    masked_seed = _xor_bytes(seed, seed_mask)
    encoded_message = b"\x00" + masked_seed + masked_db

    message_int = _os2ip(encoded_message)
    ciphertext_int = _rsaep(recipient_public_key, message_int)
    return _i2osp(ciphertext_int, k)


def decrypt_message(
    ciphertext: bytes,
    own_private_key: RSAPrivateKey,
    label: bytes = OAEP_SHA256_LABEL,
) -> bytes:
    """
    Decrypt RSA-OAEP(SHA-256) ciphertext and return raw plaintext bytes.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")

    ciphertext = bytes(ciphertext)
    k = own_private_key.size_bytes()
    h_len = SHA256_DIGEST_SIZE

    if len(ciphertext) != k:
        raise RSADecryptionError(
            f"Ciphertext length must be exactly {k} bytes for this key."
        )

    ciphertext_int = _os2ip(ciphertext)
    message_int = _rsadp(own_private_key, ciphertext_int)
    encoded_message = _i2osp(message_int, k)

    if len(encoded_message) < (2 * h_len) + 2 or encoded_message[0] != 0:
        raise RSADecryptionError("Invalid OAEP encoded message")

    masked_seed = encoded_message[1 : 1 + h_len]
    masked_db = encoded_message[1 + h_len :]
    seed_mask = mgf1(masked_db, h_len)
    seed = _xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - h_len - 1)
    db = _xor_bytes(masked_db, db_mask)
    l_hash = sha256_digest(label)

    if not hmac.compare_digest(db[:h_len], l_hash):
        raise RSADecryptionError("OAEP label hash mismatch")

    separator_index = None
    for index, byte_value in enumerate(db[h_len:], start=h_len):
        if byte_value == 1:
            separator_index = index
            break
        if byte_value != 0:
            raise RSADecryptionError("Invalid OAEP padding")

    if separator_index is None:
        raise RSADecryptionError("OAEP separator byte not found")

    return db[separator_index + 1 :]


def decrypt_message_to_text(
    ciphertext: bytes,
    own_private_key: RSAPrivateKey,
    label: bytes = OAEP_SHA256_LABEL,
    encoding: str = DEFAULT_ENCODING,
) -> str:
    """Decrypt ciphertext and decode the plaintext as UTF-8."""
    plaintext = decrypt_message(ciphertext, own_private_key, label=label)
    return plaintext.decode(encoding)


def sign_data(
    data: Union[str, bytes],
    own_private_key: RSAPrivateKey,
    encoding: str = DEFAULT_ENCODING,
    salt_length: int = SHA256_DIGEST_SIZE,
) -> bytes:
    """
    Sign data with RSA-PSS(SHA-256).

    Returns raw signature bytes.
    """
    if salt_length <= 0:
        raise ValueError("salt_length must be positive")

    message = _ensure_bytes(data, encoding)
    em_bits = own_private_key.size_bits() - 1
    em_len = (em_bits + 7) // 8
    h_len = SHA256_DIGEST_SIZE

    if em_len < h_len + salt_length + 2:
        raise RSASignatureError("Key is too small for the requested PSS salt length")

    message_hash = sha256_digest(message)
    salt = secrets.token_bytes(salt_length)
    m_prime = (b"\x00" * 8) + message_hash + salt
    hashed = sha256_digest(m_prime)
    ps = b"\x00" * (em_len - salt_length - h_len - 2)
    data_block = ps + b"\x01" + salt
    db_mask = mgf1(hashed, em_len - h_len - 1)
    masked_db = bytearray(_xor_bytes(data_block, db_mask))

    leftmost_bits = (8 * em_len) - em_bits
    if leftmost_bits:
        masked_db[0] &= 0xFF >> leftmost_bits

    encoded_message = bytes(masked_db) + hashed + b"\xbc"
    message_int = _os2ip(encoded_message)
    signature_int = _rsasp1(own_private_key, message_int)
    return _i2osp(signature_int, own_private_key.size_bytes())


def verify_signature(
    data: Union[str, bytes],
    signature: bytes,
    sender_public_key: RSAPublicKey,
    encoding: str = DEFAULT_ENCODING,
    salt_length: int = SHA256_DIGEST_SIZE,
) -> bool:
    """
    Verify an RSA-PSS(SHA-256) signature.

    Returns True if valid, False otherwise.
    """
    if not isinstance(signature, (bytes, bytearray)):
        return False
    if salt_length <= 0:
        return False

    signature = bytes(signature)
    message = _ensure_bytes(data, encoding)
    em_bits = sender_public_key.size_bits() - 1
    em_len = (em_bits + 7) // 8
    h_len = SHA256_DIGEST_SIZE

    if len(signature) != sender_public_key.size_bytes():
        return False
    if em_len < h_len + salt_length + 2:
        return False

    try:
        signature_int = _os2ip(signature)
        message_int = _rsaep(sender_public_key, signature_int)
        encoded_message = _i2osp(message_int, em_len)
    except RSAError:
        return False

    if not encoded_message or encoded_message[-1] != 0xBC:
        return False

    masked_db = encoded_message[: em_len - h_len - 1]
    hashed = encoded_message[em_len - h_len - 1 : em_len - 1]
    leftmost_bits = (8 * em_len) - em_bits

    if leftmost_bits and (masked_db[0] >> (8 - leftmost_bits)) != 0:
        return False

    db_mask = mgf1(hashed, em_len - h_len - 1)
    data_block = bytearray(_xor_bytes(masked_db, db_mask))
    if leftmost_bits:
        data_block[0] &= 0xFF >> leftmost_bits
    data_block = bytes(data_block)

    ps_length = em_len - h_len - salt_length - 2
    if data_block[:ps_length] != (b"\x00" * ps_length):
        return False
    if data_block[ps_length] != 0x01:
        return False

    salt = data_block[-salt_length:]
    message_hash = sha256_digest(message)
    expected_hash = sha256_digest((b"\x00" * 8) + message_hash + salt)
    return hmac.compare_digest(hashed, expected_hash)


def sha256_digest(data: Union[str, bytes], encoding: str = DEFAULT_ENCODING) -> bytes:
    """Return the SHA-256 digest as raw bytes."""
    return hashlib.sha256(_ensure_bytes(data, encoding)).digest()


def sha256_hex(data: Union[str, bytes], encoding: str = DEFAULT_ENCODING) -> str:
    """Return the SHA-256 digest as a hexadecimal string."""
    return hashlib.sha256(_ensure_bytes(data, encoding)).hexdigest()


def mgf1(seed: bytes, length: int) -> bytes:
    """Mask generation function MGF1 using SHA-256."""
    if length < 0:
        raise ValueError("length must be non-negative")

    output = bytearray()
    counter = 0
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, "big")
        output.extend(hashlib.sha256(seed + counter_bytes).digest())
        counter += 1
    return bytes(output[:length])


def public_key_fingerprint(public_key: RSAPublicKey) -> str:
    """
    Return a short SHA-256 fingerprint of the PEM-encoded public key.

    Useful for debugging or manually checking key exchange.
    """
    der = _pem_decode(serialize_public_key(public_key), _PEM_PUBLIC_HEADER)
    fingerprint = hashlib.sha256(der).hexdigest()
    return ":".join(fingerprint[index : index + 2] for index in range(0, 32, 2))


def message_byte_length(
    message: Union[str, bytes],
    encoding: str = DEFAULT_ENCODING,
) -> int:
    """Return the UTF-8 byte length of a message."""
    return len(_ensure_bytes(message, encoding))


def message_fits_rsa_limit(
    message: Union[str, bytes],
    public_key: RSAPublicKey,
    encoding: str = DEFAULT_ENCODING,
) -> bool:
    """Return True if the message fits the OAEP/SHA-256 size limit."""
    return message_byte_length(message, encoding) <= public_key.max_oaep_message_length()


def ciphertext_to_base64(ciphertext: bytes) -> str:
    """Encode ciphertext bytes as Base64 text for JSON/socket transport."""
    return base64.b64encode(ciphertext).decode("ascii")


def ciphertext_from_base64(encoded_ciphertext: str) -> bytes:
    """Decode Base64 ciphertext text back to raw bytes."""
    return base64.b64decode(encoded_ciphertext.encode("ascii"), validate=True)


def signature_to_base64(signature: bytes) -> str:
    """Encode signature bytes as Base64 text for JSON/socket transport."""
    return base64.b64encode(signature).decode("ascii")


def signature_from_base64(encoded_signature: str) -> bytes:
    """Decode Base64 signature text back to raw bytes."""
    return base64.b64decode(encoded_signature.encode("ascii"), validate=True)


def run_self_test(key_size: int = DEFAULT_KEY_SIZE) -> dict[str, Union[bool, int, str]]:
    """
    Run an end-to-end RSA self-test and return a summary dictionary.

    This is useful for quickly checking:
    - key generation
    - PEM export/import
    - encryption/decryption
    - signing/verification
    """
    private_key, public_key = generate_keypair(key_size=key_size)
    max_message_bytes = public_key.max_oaep_message_length()
    sample_message = "RSA smoke test"
    if message_byte_length(sample_message) > max_message_bytes:
        raise RSAError("Self-test sample message does not fit the current key size")

    ciphertext = encrypt_message(sample_message, public_key)
    decrypted_message = decrypt_message_to_text(ciphertext, private_key)
    signature = sign_data(sample_message, private_key)
    signature_valid = verify_signature(sample_message, signature, public_key)

    public_pem = serialize_public_key(public_key)
    private_pem = serialize_private_key(private_key)
    imported_public_key = deserialize_public_key(public_pem)
    imported_private_key = deserialize_private_key(private_pem)

    with tempfile.TemporaryDirectory() as temp_dir:
        public_path = Path(temp_dir) / "public_key.pem"
        private_path = Path(temp_dir) / "private_key.pem"
        save_public_key(public_key, public_path)
        save_private_key(private_key, private_path)
        loaded_public_key = load_public_key(public_path)
        loaded_private_key = load_private_key(private_path)

    ciphertext_roundtrip = encrypt_message(sample_message, imported_public_key)
    decrypted_roundtrip = decrypt_message_to_text(ciphertext_roundtrip, imported_private_key)
    ciphertext_from_loaded_keys = encrypt_message(sample_message, loaded_public_key)
    decrypted_from_loaded_keys = decrypt_message_to_text(
        ciphertext_from_loaded_keys,
        loaded_private_key,
    )
    tampered_signature_valid = verify_signature(
        sample_message + "!",
        signature,
        public_key,
    )

    return {
        "key_size_bits": key_size,
        "public_key_size_bytes": public_key.size_bytes(),
        "oaep_max_message_bytes": max_message_bytes,
        "sample_message_bytes": message_byte_length(sample_message),
        "ciphertext_bytes": len(ciphertext),
        "signature_bytes": len(signature),
        "signature_valid": signature_valid,
        "tampered_signature_valid": tampered_signature_valid,
        "decryption_ok": decrypted_message == sample_message,
        "roundtrip_after_import_ok": decrypted_roundtrip == sample_message,
        "roundtrip_after_file_save_ok": decrypted_from_loaded_keys == sample_message,
        "public_key_fingerprint": public_key_fingerprint(public_key),
    }


def _ensure_bytes(data: Union[str, bytes], encoding: str = DEFAULT_ENCODING) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode(encoding)
    raise TypeError("Expected str, bytes, or bytearray")


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _i2osp(value: int, length: int) -> bytes:
    if value < 0:
        raise ValueError("Integer must be non-negative")
    if value >= 256**length:
        raise RSAError("Integer too large")
    return value.to_bytes(length, "big")


def _os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _rsaep(public_key: RSAPublicKey, message_int: int) -> int:
    if not 0 <= message_int < public_key.n:
        raise RSAEncryptionError("Message representative out of range")
    return pow(message_int, public_key.e, public_key.n)


def _rsadp(private_key: RSAPrivateKey, ciphertext_int: int) -> int:
    if not 0 <= ciphertext_int < private_key.n:
        raise RSADecryptionError("Ciphertext representative out of range")
    return pow(ciphertext_int, private_key.d, private_key.n)


def _rsasp1(private_key: RSAPrivateKey, message_int: int) -> int:
    if not 0 <= message_int < private_key.n:
        raise RSASignatureError("Message representative out of range")
    return pow(message_int, private_key.d, private_key.n)


def _generate_prime(bits: int, public_exponent: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if any(candidate % prime == 0 for prime in _SMALL_PRIMES):
            continue
        if (candidate - 1) % public_exponent == 0:
            continue
        if _is_probable_prime(candidate):
            return candidate


def _is_probable_prime(candidate: int, rounds: int = 40) -> bool:
    if candidate < 2:
        return False
    if candidate in (2, 3):
        return True
    if candidate % 2 == 0:
        return False

    for prime in _SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        x = pow(base, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _der_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("Length cannot be negative")
    if length < 0x80:
        return bytes([length])

    encoded = bytearray()
    while length > 0:
        encoded.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(encoded)]) + bytes(encoded)


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("DER INTEGER only supports non-negative values here")

    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_length(len(raw)) + raw


def _der_sequence(*items: bytes) -> bytes:
    payload = b"".join(items)
    return b"\x30" + _der_length(len(payload)) + payload


def _der_octet_string(data: bytes) -> bytes:
    return b"\x04" + _der_length(len(data)) + data


def _der_bit_string(data: bytes) -> bytes:
    payload = b"\x00" + data
    return b"\x03" + _der_length(len(payload)) + payload


def _der_null() -> bytes:
    return b"\x05\x00"


def _decode_der_integer(encoded: bytes) -> int:
    if not encoded:
        raise RSAKeyFormatError("Empty DER INTEGER")
    if len(encoded) > 1 and encoded[0] == 0 and encoded[1] < 0x80:
        encoded = encoded[1:]
    return int.from_bytes(encoded, "big")


def _pem_encode(label: str, der_data: bytes) -> bytes:
    base64_text = base64.b64encode(der_data).decode("ascii")
    lines = [base64_text[index : index + 64] for index in range(0, len(base64_text), 64)]
    body = "\n".join(lines)
    pem = f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"
    return pem.encode("ascii")


def _pem_decode(pem_data: Union[str, bytes], expected_label: str) -> bytes:
    if isinstance(pem_data, bytes):
        pem_text = pem_data.decode("ascii")
    elif isinstance(pem_data, str):
        pem_text = pem_data
    else:
        raise TypeError("PEM data must be str or bytes")

    begin_marker = f"-----BEGIN {expected_label}-----"
    end_marker = f"-----END {expected_label}-----"

    if begin_marker not in pem_text or end_marker not in pem_text:
        raise RSAKeyFormatError(f"Expected PEM block {expected_label!r}")

    start = pem_text.index(begin_marker) + len(begin_marker)
    end = pem_text.index(end_marker)
    base64_body = "".join(line.strip() for line in pem_text[start:end].splitlines() if line.strip())
    try:
        return base64.b64decode(base64_body.encode("ascii"), validate=True)
    except Exception as exc:  # pragma: no cover - defensive path
        raise RSAKeyFormatError("Invalid PEM Base64 body") from exc


class _DERReader:
    def __init__(self, data: bytes):
        self._data = data
        self._position = 0

    def _read_byte(self) -> int:
        if self._position >= len(self._data):
            raise RSAKeyFormatError("Unexpected end of DER data")
        value = self._data[self._position]
        self._position += 1
        return value

    def _read_bytes(self, count: int) -> bytes:
        if self._position + count > len(self._data):
            raise RSAKeyFormatError("Unexpected end of DER data")
        chunk = self._data[self._position : self._position + count]
        self._position += count
        return chunk

    def _read_length(self) -> int:
        first = self._read_byte()
        if first < 0x80:
            return first
        size = first & 0x7F
        if size == 0:
            raise RSAKeyFormatError("Indefinite DER length is not supported")
        length_bytes = self._read_bytes(size)
        return int.from_bytes(length_bytes, "big")

    def read_tlv(self, expected_tag: int) -> bytes:
        tag = self._read_byte()
        if tag != expected_tag:
            raise RSAKeyFormatError(
                f"Unexpected DER tag 0x{tag:02x}; expected 0x{expected_tag:02x}"
            )
        length = self._read_length()
        return self._read_bytes(length)

    def ensure_exhausted(self) -> None:
        if self._position != len(self._data):
            raise RSAKeyFormatError("Trailing bytes found in DER data")


if __name__ == "__main__":
    print("Running rsa.py self-test...")
    results = run_self_test()
    for key, value in results.items():
        print(f"{key}: {value}")
