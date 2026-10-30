from attack_simulator import AttackSimulator
from srp_server import SRPDatabase
from srp_client import SRPClient

db = SRPDatabase("test_srp.db")
db.clear_database()
u, s, v = SRPClient.generate_registration_bundle("bob", "password")
db.register_user(u, s, v)

sim = AttackSimulator(db)

r1 = sim.simulate_stolen_verifier_impersonation_attack("bob")
print("1. Stolen Verifier Result:", r1["result"])

r2 = sim.simulate_replay_attack("bob", "password")
print("2. Replay Attack Result:", r2["result"])

r3 = sim.simulate_mitm_tampering_attack("bob", "password")
print("3. MitM Tampering Result:", r3["result"])

r4 = sim.simulate_phishing_rogue_server("bob", "password")
print("4. Phishing Server Result:", r4["result"])

r5 = sim.simulate_stolen_db_offline_dictionary_attack("bob")
print(f"5. Dictionary Attack Cracked: {r5['cracked']}, Attempts: {r5['attempts']}, Avg ms: {r5['avg_ms_per_guess']}")
