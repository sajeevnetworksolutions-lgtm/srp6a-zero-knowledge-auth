"""
Zero-Knowledge Password Authentication Protocol (SRP-6a)
Module 4: Attack Simulator & Breach-Resistance Verification Engine
Tests:
1. Offline Dictionary Attack on Dumped Database (RockYou simulated dictionary)
2. Stolen Verifier Impersonation Attack
3. Active Man-in-the-Middle (MitM) Key Tampering
4. Replay Attack Detection
5. Phishing / Rogue Server Impersonation
"""

import time
import secrets
from typing import Dict, Any, List
import srp_params as params
from srp_client import SRPClient
from srp_server import SRPDatabase, SRPServerSession


ROCKYOU_SAMPLE_WORDLIST = [
    "password", "123456", "12345678", "1234", "qwerty", "12345", "dragon",
    "pussycat", "baseball", "football", "master", "monkey", "shadow",
    "mustang", "superman", "harley", "iloveyou", "trustno1", "computer",
    "admin", "welcome", "princess", "secret", "killer", "letmein",
    "charlie", "jordan", "michael", "cookie", "sunshine", "jessica",
    "buster", "thomas", "pepper", "bullet", "freedom", "pepper",
    "phoenix", "starwars", "orange", "yellow", "testing", "thunder",
    "ZeroKnowledge2026!", "crypto_master_key", "unbreakable_auth_token"
]


class AttackSimulator:
    """Simulates real-world offensive attacks against SRP-6a client-server architecture."""

    def __init__(self, db: SRPDatabase):
        self.db = db

    def simulate_stolen_db_offline_dictionary_attack(
        self, target_username: str, wordlist: List[str] = None
    ) -> Dict[str, Any]:
        """
        Simulates an attacker who breached the database and stole (salt, verifier).
        Attacker attempts an offline dictionary attack to recover password P.
        Demonstrates the immense computational cost of 2048-bit modular exponentiations.
        """
        if wordlist is None:
            wordlist = ROCKYOU_SAMPLE_WORDLIST

        user_record = self.db.get_user(target_username)
        if not user_record:
            return {"error": f"Target user '{target_username}' not in database."}

        target_salt = user_record["salt"]
        target_verifier = user_record["verifier"]

        start_time = time.perf_counter()
        attempts = 0
        cracked = False
        cracked_password = None

        for candidate in wordlist:
            attempts += 1
            # Step 1: candidate x' = H(salt, candidate)
            cand_x = params.compute_x(target_salt, candidate, target_username)
            # Step 2: candidate v' = g^(x') mod N (Heavy 2048-bit BigInt exponentiation)
            cand_v = params.compute_verifier(cand_x)

            if cand_v == target_verifier:
                cracked = True
                cracked_password = candidate
                break

        elapsed = time.perf_counter() - start_time
        ms_per_guess = (elapsed / attempts) * 1000 if attempts > 0 else 0

        return {
            "attack_type": "Offline Dictionary Attack on Database Dump",
            "target_user": target_username,
            "target_verifier_hex": hex(target_verifier)[:32] + "...",
            "attempts": attempts,
            "total_time_seconds": round(elapsed, 4),
            "avg_ms_per_guess": round(ms_per_guess, 3),
            "cracked": cracked,
            "recovered_password": cracked_password,
            "security_analysis": (
                "Even on a leaked database, the attacker MUST execute full 2048-bit modular "
                "exponentiations for every single word. Compare with traditional MD5/SHA256 "
                "where GPUs test 100,000,000,000 hashes/sec. For strong passwords, "
                "the discrete logarithm problem log_g(v) mod N provides total breach immunity."
            )
        }

    def simulate_stolen_verifier_impersonation_attack(
        self, target_username: str
    ) -> Dict[str, Any]:
        """
        Attacker attempts to authenticate as the target user using ONLY the stolen verifier v.
        Shows that possessing 'v' in the database DOES NOT allow an attacker to log in.
        """
        user_record = self.db.get_user(target_username)
        if not user_record:
            return {"error": f"Target user '{target_username}' not in database."}

        stolen_v = user_record["verifier"]
        stolen_salt = user_record["salt"]

        # Attacker connects to server
        server = SRPServerSession(self.db)
        attacker_a = secrets.randbelow(params.N - 2) + 2
        attacker_A = pow(params.g, attacker_a, params.N)

        # Server responds with (salt, B)
        salt_recv, B_recv = server.handle_client_init(target_username, attacker_A)

        # The attacker has 'stolen_v', but DOES NOT have password P or x.
        # Can attacker compute S = (B - k*v)^(a + u*x) mod N?
        # No! x is private to the user.
        # If attacker attempts to substitute a bogus x or use v directly:
        fake_x = stolen_v % params.N
        u = params.compute_u(attacker_A, B_recv)
        base = (B_recv - (params.k * stolen_v)) % params.N
        exp = attacker_a + (u * fake_x)
        bogus_S = pow(base, exp, params.N)
        bogus_K = params.sha256_hash(bogus_S)

        bogus_M1 = params.compute_m1(target_username, salt_recv, attacker_A, B_recv, bogus_K)

        success, M2, token = server.verify_client_evidence(bogus_M1)

        return {
            "attack_type": "Stolen Verifier Direct Login Attack",
            "target_user": target_username,
            "attacker_had_verifier": True,
            "attacker_had_password": False,
            "server_accepted_login": success,
            "result": "REJECTED (Access Denied)" if not success else "VULNERABLE",
            "mathematical_explanation": (
                "The server requires proof of knowledge of x = H(s, P). "
                "Because v = g^x mod N, finding x from v requires solving the Discrete "
                "Logarithm Problem over a 2048-bit safe prime field (RFC 5054). "
                "Therefore, possessing the leaked database verifier gives 0% ability to impersonate the user."
            )
        }

    def simulate_mitm_tampering_attack(
        self, username: str, password: str
    ) -> Dict[str, Any]:
        """
        Simulates active Man-in-the-Middle attacker who intercepts and tampers with ephemeral public keys.
        """
        # Register user
        u, salt, v = SRPClient.generate_registration_bundle(username, password)
        self.db.register_user(u, salt, v)

        client = SRPClient(username, password)
        client_user, A_legit = client.start_authentication()

        server = SRPServerSession(self.db)

        # MitM intercepts A and tampers with it
        A_tampered = (A_legit + 1337) % params.N
        server_salt, B_legit = server.handle_client_init(client_user, A_tampered)

        # Client receives legitimate B (or tampered B)
        client_M1 = client.process_challenge(server_salt, B_legit)

        # Server attempts verification
        success, M2, token = server.verify_client_evidence(client_M1)

        return {
            "attack_type": "Active MitM Packet Tampering Attack",
            "packet_tampered": "Client Ephemeral Key A -> A + 1337",
            "server_verified_M1": success,
            "client_authenticated": client.authenticated,
            "result": "TAMPERING DETECTED & ABORTED" if not success else "VULNERABLE",
            "mathematical_explanation": (
                "SRP-6a binds both ephemeral keys via scrambling parameter u = H(A, B). "
                "Any bit alteration in A or B causes u_client != u_server and mismatched session secrets, "
                "causing instant failure at the evidence verification step before any data is sent."
            )
        }

    def simulate_replay_attack(
        self, username: str, password: str
    ) -> Dict[str, Any]:
        """
        Simulates an eavesdropper recording a valid handshake transcript and replaying it later.
        """
        u, salt, v = SRPClient.generate_registration_bundle(username, password)
        self.db.register_user(u, salt, v)

        # Legitimate Session 1
        client1 = SRPClient(username, password)
        user_req, A1 = client1.start_authentication()

        server1 = SRPServerSession(self.db)
        salt1, B1 = server1.handle_client_init(user_req, A1)
        M1_legit = client1.process_challenge(salt1, B1)
        s1_success, M2_legit, token1 = server1.verify_client_evidence(M1_legit)

        # Attacker sniffs (A1, M1_legit) and attempts Session 2 replay
        server2 = SRPServerSession(self.db)
        # Server generates NEW ephemeral b2, B2
        salt2, B2 = server2.handle_client_init(user_req, A1)

        # Attacker tries to replay M1_legit
        replay_success, M2_replay, token2 = server2.verify_client_evidence(M1_legit)

        return {
            "attack_type": "Replay Attack (Captured Handshake Replay)",
            "session_1_legitimate_auth": s1_success,
            "session_2_replayed_auth": replay_success,
            "result": "REPLAY REJECTED" if not replay_success else "VULNERABLE",
            "mathematical_explanation": (
                "Each session uses unique, cryptographically random ephemeral keys (a, b). "
                "Because B2 != B1, u2 = H(A1, B2) != u1, which completely changes the required M1. "
                "Replaying old authentication packets always fails."
            )
        }

    def simulate_phishing_rogue_server(
        self, username: str, password: str
    ) -> Dict[str, Any]:
        """
        Simulates a malicious phishing server trying to authenticate the client to steal credentials.
        Shows how mutual authentication protects the client.
        """
        client = SRPClient(username, password)
        user_req, A = client.start_authentication()

        # Rogue server has no access to real verifier v
        fake_salt = secrets.token_bytes(16)
        fake_b = secrets.randbelow(params.N - 2) + 2
        fake_B = pow(params.g, fake_b, params.N)

        # Client sends M1
        client_M1 = client.process_challenge(fake_salt, fake_B)

        # Rogue server cannot generate valid M2 because it does not know S
        bogus_M2 = secrets.token_bytes(32)

        try:
            client.verify_server_evidence(bogus_M2)
            phishing_detected = False
        except PermissionError:
            phishing_detected = True

        return {
            "attack_type": "Rogue Server / Phishing Impersonation Attack",
            "mutual_proof_requested": "M2 = H(A, M1, K)",
            "rogue_server_fooled_client": not phishing_detected,
            "result": "PHISHING SERVER DETECTED & CLIENT ABORTED" if phishing_detected else "VULNERABLE",
            "mathematical_explanation": (
                "Unlike standard password forms where users send passwords blindly to phishing sites, "
                "SRP-6a enforces MUTUAL cryptographic verification: the client requires proof M2 from "
                "the server. A fake server cannot generate M2 without the true shared secret S."
            )
        }
