"""
Zero-Knowledge Password Authentication Protocol (SRP-6a)
Module 1: Safe Prime Parameters and Cryptographic Helpers (RFC 5054 & NIST FIPS 180-4)
"""

import hashlib
import secrets
from typing import Tuple

# RFC 5054 2048-bit Safe Prime Modulus (N = 2q + 1)
# Group Generator g = 2
RFC_5054_2048_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294"
    "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D"
    "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB"
    "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74"
    "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A"
    "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D"
    "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73"
    "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F"
    "9E4AFF73"
)

# 2048-bit BigInt Safe Prime Modulus
N = int(RFC_5054_2048_HEX, 16)

# Primitive Generator
g = 2

# Number of bytes in modulus N (2048 bits = 256 bytes)
N_LEN = 256


def int_to_bytes(val: int, length: int = N_LEN) -> bytes:
    """Convert an integer to a big-endian fixed-length byte string."""
    return val.to_bytes(length, byteorder="big")


def bytes_to_int(data: bytes) -> int:
    """Convert big-endian byte sequence to integer."""
    return int.from_bytes(data, byteorder="big")


def sha256_hash(*args) -> bytes:
    """
    Compute cryptographic SHA-256 hash of concatenated inputs.
    Inputs can be bytes, strings, or integers.
    """
    hasher = hashlib.sha256()
    for arg in args:
        if isinstance(arg, int):
            hasher.update(int_to_bytes(arg))
        elif isinstance(arg, str):
            hasher.update(arg.encode("utf-8"))
        elif isinstance(arg, bytes):
            hasher.update(arg)
        else:
            raise TypeError(f"Unsupported data type for hashing: {type(arg)}")
    return hasher.digest()


def sha256_int(*args) -> int:
    """Compute SHA-256 hash and return as integer."""
    return bytes_to_int(sha256_hash(*args))


# RFC 5054 SRP-6a Multiplier Parameter k = H(N, g)
k = sha256_int(N, g)


def compute_x(salt: bytes, password: str, username: str = None) -> int:
    """
    Derive the private key x from salt and password:
    x = H(salt, password)
    Optionally follows RFC 5054: x = H(salt || H(username || ':' || password))
    """
    if username is not None:
        inner = hashlib.sha256(f"{username}:{password}".encode("utf-8")).digest()
        x_bytes = hashlib.sha256(salt + inner).digest()
    else:
        x_bytes = hashlib.sha256(salt + password.encode("utf-8")).digest()
    return bytes_to_int(x_bytes)


def compute_verifier(x: int) -> int:
    """Compute the zero-knowledge mathematical verifier v = g^x mod N."""
    return pow(g, x, N)


def compute_u(A: int, B: int) -> int:
    """
    Compute random scrambling parameter u = H(A, B).
    Both parties compute this independently.
    """
    return sha256_int(A, B)


def compute_m1(username: str, salt: bytes, A: int, B: int, K: bytes) -> bytes:
    """
    Client Evidence M1 = H(username, salt, A, B, K)
    Proves to the server that client knows password without sending it.
    """
    return sha256_hash(username, salt, A, B, K)


def compute_m2(A: int, M1: bytes, K: bytes) -> bytes:
    """
    Server Evidence M2 = H(A, M1, K)
    Proves to the client that server possesses the correct verifier v.
    """
    return sha256_hash(A, M1, K)
