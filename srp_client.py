"""
Zero-Knowledge Password Authentication Protocol (SRP-6a)
Module 2: Client Prover Engine (RFC 5054 Compliant)
"""

import secrets
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import srp_params as params


class SRPClient:
    """
    Client Prover Engine.
    Computes private exponents and ephemeral key pairs without ever sending
    the plaintext password or its raw hash over the network.
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.a: int = 0
        self.A: int = 0
        self.s: bytes = b""
        self.B: int = 0
        self.u: int = 0
        self.S: int = 0
        self.K: bytes = b""
        self.M1: bytes = b""
        self.authenticated: bool = False

    @staticmethod
    def generate_registration_bundle(username: str, password: str, salt_bytes: int = 16) -> Tuple[str, bytes, int]:
        """
        Generate registration data to store on the server.
        Only (username, salt, verifier v) are sent.
        The password P and secret exponent x NEVER leave the client.
        """
        salt = secrets.token_bytes(salt_bytes)
        x = params.compute_x(salt, password, username)
        v = params.compute_verifier(x)
        return username, salt, v

    def start_authentication(self) -> Tuple[str, int]:
        """
        Phase 1 of Handshake:
        Client selects random ephemeral private scalar 'a' and generates public key A = g^a mod N.
        Returns (username, A) to send to server.
        """
        # RFC 5054 recommends ephemeral private scalar 'a' to be at least 256 bits long
        # for optimal sub-15ms performance while maintaining 128-bit security level.
        self.a = secrets.randbits(256) | (1 << 255)
        self.A = pow(params.g, self.a, params.N)

        if self.A % params.N == 0:
            raise ValueError("Security violation: Ephemeral key A mod N is 0.")

        return self.username, self.A

    def process_challenge(self, salt: bytes, B: int) -> bytes:
        """
        Phase 2 of Handshake:
        Client receives (salt, B) from server.
        Calculates:
          u = H(A, B)
          x = H(salt, password)
          S_client = (B - k * g^x)^(a + u * x) mod N
          K_client = H(S_client)
          M1 = H(username, salt, A, B, K_client)
        Returns M1 proof to send to server.
        """
        self.s = salt
        self.B = B

        # Abort if server ephemeral key B is 0 mod N (Small subgroup / malicious server protection)
        if self.B % params.N == 0:
            raise ValueError("Security violation: Server ephemeral B mod N is 0.")

        # Compute scrambling parameter u = H(A, B)
        self.u = params.compute_u(self.A, self.B)
        if self.u == 0:
            raise ValueError("Security violation: Scrambler parameter u is 0.")

        # Calculate private password exponent x
        x = params.compute_x(self.s, self.password, self.username)
        g_x = pow(params.g, x, params.N)

        # Base: (B - k * g^x) mod N
        base = (self.B - (params.k * g_x)) % params.N

        # Exponent: (a + u * x)
        exp = self.a + (self.u * x)

        # Zero-Knowledge Shared Secret S_client
        self.S = pow(base, exp, params.N)

        # Session Key K = H(S)
        self.K = params.sha256_hash(self.S)

        # Evidence M1 proving password knowledge
        self.M1 = params.compute_m1(self.username, self.s, self.A, self.B, self.K)
        return self.M1

    def verify_server_evidence(self, M2: bytes) -> bool:
        """
        Phase 3 of Handshake:
        Mutual Authentication Verification.
        Verifies that server evidence M2 matches H(A, M1, K).
        If valid, mutual trust is established and authenticated session is active.
        """
        expected_m2 = params.compute_m2(self.A, self.M1, self.K)
        if secrets.compare_digest(M2, expected_m2):
            self.authenticated = True
            return True
        else:
            self.authenticated = False
            raise PermissionError("Server evidence verification failed. Rogue server detected!")

    def encrypt_session_message(self, plaintext: str) -> Dict[str, str]:
        """Encrypt message with shared session key K using AES-GCM-256."""
        if not self.authenticated:
            raise RuntimeError("Cannot encrypt without authenticated session.")
        aesgcm = AESGCM(self.K)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex()
        }

    def decrypt_session_message(self, nonce_hex: str, ciphertext_hex: str) -> str:
        """Decrypt message using shared session key K."""
        if not self.authenticated:
            raise RuntimeError("Cannot decrypt without authenticated session.")
        aesgcm = AESGCM(self.K)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode("utf-8")
