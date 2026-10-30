"""
Zero-Knowledge Password Authentication Protocol (SRP-6a)
Module 3: Server Verifier Node & Breach-Immune Database Engine
"""

import sqlite3
import secrets
from typing import Tuple, Dict, Any, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import srp_params as params


class SRPDatabase:
    """
    Breach-Immune User Database.
    Stores only (username, salt, verifier v).
    Zero plaintext passwords and zero password hashes are stored.
    """

    def __init__(self, db_path: str = "srp_server.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    salt_hex TEXT NOT NULL,
                    verifier_hex TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def register_user(self, username: str, salt: bytes, verifier: int) -> bool:
        """Register a user storing only salt and mathematical verifier v = g^x mod N."""
        salt_hex = salt.hex()
        verifier_hex = hex(verifier)[2:]
        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (username, salt_hex, verifier_hex)
                    VALUES (?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        salt_hex=excluded.salt_hex,
                        verifier_hex=excluded.verifier_hex
                    """,
                    (username, salt_hex, verifier_hex)
                )
            return True
        except sqlite3.Error:
            return False

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored cryptographic tuple (salt, verifier) for a username."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT username, salt_hex, verifier_hex, created_at FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()
        if row:
            return {
                "username": row[0],
                "salt": bytes.fromhex(row[1]),
                "verifier": int(row[2], 16),
                "created_at": row[3]
            }
        return None

    def dump_database(self) -> List[Dict[str, Any]]:
        """Simulate a complete database dump stolen by an attacker."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, username, salt_hex, verifier_hex, created_at FROM users")
        rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "username": r[1],
                "salt_hex": r[2],
                "verifier_hex": r[3],
                "created_at": r[4]
            }
            for r in rows
        ]

    def clear_database(self):
        """Reset the database table for testing."""
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM users")


class SRPServerSession:
    """
    SRP-6a Server State Machine.
    Handles ephemeral key generation, zero-knowledge verification,
    and mutual evidence generation.
    """

    def __init__(self, db: SRPDatabase):
        self.db = db
        self.username: str = ""
        self.salt: bytes = b""
        self.v: int = 0
        self.A: int = 0
        self.b: int = 0
        self.B: int = 0
        self.u: int = 0
        self.S: int = 0
        self.K: bytes = b""
        self.session_token: Optional[str] = None
        self.authenticated: bool = False

    def handle_client_init(self, username: str, A: int) -> Tuple[bytes, int]:
        """
        Step 1 of Server Authentication:
        Receives (username, A) from client.
        Validates A mod N != 0.
        Fetches (s, v) from database.
        Generates random b, computes B = (k*v + g^b) mod N.
        Computes scrambling parameter u = H(A, B).
        Derives shared secret S_server = (A * v^u)^b mod N and session key K.
        Returns (salt, B) to client.
        """
        self.username = username
        self.A = A

        # Small subgroup attack prevention: A mod N must never be 0
        if self.A % params.N == 0:
            raise ValueError("Security violation: Client ephemeral A mod N is 0.")

        user_data = self.db.get_user(username)
        if not user_data:
            raise KeyError(f"User '{username}' not found in database.")

        self.salt = user_data["salt"]
        self.v = user_data["verifier"]

        # RFC 5054 specifies ephemeral private scalar 'b' should be at least 256 bits long
        self.b = secrets.randbits(256) | (1 << 255)

        # Ephemeral public key B = (k * v + g^b) mod N
        g_b = pow(params.g, self.b, params.N)
        self.B = ((params.k * self.v) + g_b) % params.N

        if self.B % params.N == 0:
            raise ValueError("Security violation: Server ephemeral B mod N is 0.")

        # Compute scrambling parameter u = H(A, B)
        self.u = params.compute_u(self.A, self.B)
        if self.u == 0:
            raise ValueError("Security violation: Scrambling parameter u is 0.")

        # Shared secret S_server = (A * v^u)^b mod N
        v_u = pow(self.v, self.u, params.N)
        base = (self.A * v_u) % params.N
        self.S = pow(base, self.b, params.N)

        # Session key K = H(S)
        self.K = params.sha256_hash(self.S)

        return self.salt, self.B

    def verify_client_evidence(self, M1: bytes) -> Tuple[bool, bytes, Optional[str]]:
        """
        Step 2 of Server Authentication:
        Receives client evidence M1.
        Calculates expected M1 = H(username, salt, A, B, K_server).
        If matching, generates mutual proof M2 = H(A, M1, K) and session token.
        """
        expected_m1 = params.compute_m1(self.username, self.salt, self.A, self.B, self.K)
        if secrets.compare_digest(M1, expected_m1):
            self.authenticated = True
            M2 = params.compute_m2(self.A, M1, self.K)
            self.session_token = secrets.token_hex(24)
            return True, M2, self.session_token
        else:
            self.authenticated = False
            return False, b"", None

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
