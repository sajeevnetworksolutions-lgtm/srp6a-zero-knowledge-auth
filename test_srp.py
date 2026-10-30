"""
Verification and Test Suite for Zero-Knowledge SRP-6a Authentication System
Tests mathematical equality, handshake validity, wrong password rejection,
and small-subgroup safety checks.
"""

import unittest
import srp_params as params
from srp_client import SRPClient
from srp_server import SRPDatabase, SRPServerSession


class TestSRP6aProtocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = SRPDatabase("test_srp.db")

    def setUp(self):
        self.db.clear_database()
        self.username = "alice_crypto"
        self.password = "SuperSecretZeroKnowledge2026!"

    def tearDown(self):
        self.db.clear_database()

    def test_registration_and_successful_handshake(self):
        """Test registration and complete mutual authentication handshake."""
        # Step 1: Registration
        u, salt, v = SRPClient.generate_registration_bundle(self.username, self.password)
        self.assertEqual(u, self.username)
        self.assertTrue(len(salt) == 16)
        self.assertTrue(v > 0)
        self.assertTrue(self.db.register_user(u, salt, v))

        # Step 2: Client starts auth
        client = SRPClient(self.username, self.password)
        user_req, A = client.start_authentication()
        self.assertEqual(user_req, self.username)
        self.assertTrue(A > 0 and A < params.N)

        # Step 3: Server receives client init
        server = SRPServerSession(self.db)
        srv_salt, B = server.handle_client_init(user_req, A)
        self.assertEqual(srv_salt, salt)
        self.assertTrue(B > 0 and B < params.N)

        # Step 4: Client computes challenge response M1
        M1 = client.process_challenge(srv_salt, B)

        # Verify mathematical equality of shared secrets S_client and S_server
        self.assertEqual(client.S, server.S, "Mathematical flaw: S_client != S_server")
        self.assertEqual(client.K, server.K, "Session key mismatch: K_client != K_server")

        # Step 5: Server verifies M1 and returns M2
        success, M2, session_token = server.verify_client_evidence(M1)
        self.assertTrue(success, "Server rejected valid client evidence M1")
        self.assertIsNotNone(session_token)

        # Step 6: Client verifies M2 (mutual authentication)
        client_auth_success = client.verify_server_evidence(M2)
        self.assertTrue(client_auth_success)
        self.assertTrue(client.authenticated)
        self.assertTrue(server.authenticated)

        # Step 7: Encrypted communication test (AES-GCM with shared K)
        test_msg = "Hello Zero-Knowledge Secure Server!"
        enc_payload = client.encrypt_session_message(test_msg)
        decrypted = server.decrypt_session_message(enc_payload["nonce_hex"], enc_payload["ciphertext_hex"])
        self.assertEqual(test_msg, decrypted)

        server_reply = "Welcome Alice! Zero password was exposed."
        reply_payload = server.encrypt_session_message(server_reply)
        decrypted_reply = client.decrypt_session_message(reply_payload["nonce_hex"], reply_payload["ciphertext_hex"])
        self.assertEqual(server_reply, decrypted_reply)

    def test_wrong_password_rejection(self):
        """Test that incorrect password fails authentication without revealing why."""
        # Register user with real password
        u, salt, v = SRPClient.generate_registration_bundle(self.username, self.password)
        self.db.register_user(u, salt, v)

        # Attacker tries wrong password
        impostor_client = SRPClient(self.username, "WrongPasswordGuess123")
        user_req, A = impostor_client.start_authentication()

        server = SRPServerSession(self.db)
        srv_salt, B = server.handle_client_init(user_req, A)

        fake_M1 = impostor_client.process_challenge(srv_salt, B)

        # Mathematical secrets MUST differ
        self.assertNotEqual(impostor_client.S, server.S)
        self.assertNotEqual(impostor_client.K, server.K)

        success, M2, token = server.verify_client_evidence(fake_M1)
        self.assertFalse(success, "Server should reject incorrect password evidence!")
        self.assertIsNone(token)

    def test_small_subgroup_attacks(self):
        """Test rejection when A mod N == 0 or B mod N == 0."""
        u, salt, v = SRPClient.generate_registration_bundle(self.username, self.password)
        self.db.register_user(u, salt, v)

        server = SRPServerSession(self.db)
        with self.assertRaises(ValueError):
            server.handle_client_init(self.username, 0)

        with self.assertRaises(ValueError):
            server.handle_client_init(self.username, params.N)


if __name__ == "__main__":
    unittest.main()
