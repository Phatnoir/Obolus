#!/usr/bin/env python3

import json
import uuid
import time
import base64
import os
from datetime import datetime, timedelta, timezone
import sqlite3
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class MfaServer:
    def __init__(self, db_path="mfa_challenges.db", public_key_path="public_key.pem"):
        self.db_path = db_path
        self.public_key_path = public_key_path
        self.setup_database()
        self.load_public_key()
    
    def load_public_key(self):
        try:
            with open(self.public_key_path, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(key_file.read())
        except Exception as e:
            print(f"Error loading public key: {e}")
            raise
    
    def setup_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            nonce TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            response TEXT,
            response_timestamp TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_challenge(self, action):
        challenge_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=60)
        nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        challenge = {
            "id": challenge_id,
            "action": action,
            "timestamp": now.isoformat(),
            "nonce": nonce,
            "expires_at": expires_at.isoformat()
        }
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO challenges (id, action, timestamp, nonce, expires_at) VALUES (?, ?, ?, ?, ?)",
            (challenge_id, action, challenge["timestamp"], nonce, challenge["expires_at"])
        )
        
        cursor.execute(
            "INSERT INTO audit_log (id, timestamp, event_type, details) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), now.isoformat(), "CHALLENGE_CREATED", json.dumps({
                "challenge_id": challenge_id,
                "action": action
            }))
        )
        
        conn.commit()
        conn.close()
        
        if "--json-only" not in sys.argv:
            print(f"Challenge created for action: {action}")
            print(f"Challenge ID: {challenge_id}")
            print(f"Challenge expires at: {expires_at.isoformat()}")
        return challenge
    
    def verify_response(self, challenge_id, response_data):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,))
        challenge_row = cursor.fetchone()
        
        if not challenge_row:
            print(f"Challenge {challenge_id} not found")
            return False, "Challenge not found"
        
        challenge_id, action, timestamp, nonce, expires_at, status, _, _ = challenge_row
        
        if status != "pending":
            print(f"Challenge {challenge_id} has already been {status}")
            return False, f"Challenge has already been {status}"
        
        now = datetime.now(timezone.utc)
        expires_at_dt = datetime.fromisoformat(expires_at)
        if now > expires_at_dt:
            cursor.execute(
                "UPDATE challenges SET status = ? WHERE id = ?",
                ("expired", challenge_id)
            )
            conn.commit()
            print(f"Challenge {challenge_id} has expired")
            return False, "Challenge has expired"
        
        try:
            response_obj = json.loads(response_data)
            response_id = response_obj.get("id")
            response_action = response_obj.get("response")
            signature_b64 = response_obj.get("signature")
            
            if response_id != challenge_id:
                raise ValueError("Response ID does not match challenge ID")
            
            signature = base64.b64decode(signature_b64)
            message = f"{challenge_id}:{action}:{nonce}:{response_action}".encode()
            self.public_key.verify(signature, message)
            
            new_status = "approved" if response_action == "approved" else "rejected"
            cursor.execute(
                "UPDATE challenges SET status = ?, response = ?, response_timestamp = ? WHERE id = ?",
                (new_status, response_data, now.isoformat(), challenge_id)
            )
            
            cursor.execute(
                "INSERT INTO audit_log (id, timestamp, event_type, details) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), now.isoformat(), "RESPONSE_VERIFIED", json.dumps({
                    "challenge_id": challenge_id,
                    "action": action,
                    "result": new_status
                }))
            )
            
            conn.commit()
            print(f"Challenge {challenge_id} has been {new_status}")
            return True, new_status
            
        except Exception as e:
            cursor.execute(
                "INSERT INTO audit_log (id, timestamp, event_type, details) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), now.isoformat(), "VERIFICATION_FAILED", json.dumps({
                    "challenge_id": challenge_id,
                    "error": str(e)
                }))
            )
            conn.commit()
            print(f"Verification failed: {e}")
            return False, f"Verification failed: {e}"
        
        finally:
            conn.close()

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python server.py [generate_challenge|verify_response] [args...]")
        sys.exit(1)
    
    server = MfaServer()
    command = sys.argv[1]

    if command == "generate_challenge":
        if len(sys.argv) < 3:
            print("Usage: python server.py generate_challenge <action> [--json-only]")
            sys.exit(1)
        action = sys.argv[2]
        challenge = server.generate_challenge(action)
        if "--json-only" in sys.argv:
            print(json.dumps(challenge, indent=2))
        else:
            print("\nChallenge JSON:")
            print(json.dumps(challenge, indent=2))
    
    elif command == "verify_response":
        if len(sys.argv) < 4:
            print("Usage: python server.py verify_response <challenge_id> <response_json>")
            sys.exit(1)
        challenge_id = sys.argv[2]
        response_data = sys.argv[3]
        result, status = server.verify_response(challenge_id, response_data)
        print(f"Verification result: {result}, Status: {status}")
    
    else:
        print(f"Unknown command: {command}")
        print("Available commands: generate_challenge, verify_response")
        sys.exit(1)
