#!/usr/bin/env python3

import json
import uuid
import time
import base64
import os
from datetime import datetime, timedelta
import sqlite3
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class MfaServer:
    def __init__(self, db_path="mfa_challenges.db", public_key_path="public_key.pem"):
        """Initialize the MFA server."""
        self.db_path = db_path
        self.public_key_path = public_key_path
        self.setup_database()
        self.load_public_key()
    
    def load_public_key(self):
        """Load the client's public key for verification."""
        try:
            with open(self.public_key_path, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(key_file.read())
        except Exception as e:
            print(f"Error loading public key: {e}")
            raise
    
    def setup_database(self):
        """Create the SQLite database and tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create challenges table
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
        
        # Create audit log table
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
        """Generate a new challenge for the specified action."""
        # Create a unique ID
        challenge_id = str(uuid.uuid4())
        
        # Get current time and expiration time (60 seconds from now)
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=60)
        
        # Generate a random nonce
        nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Create the challenge JSON
        challenge = {
            "id": challenge_id,
            "action": action,
            "timestamp": now.isoformat() + "Z",
            "nonce": nonce,
            "expires_at": expires_at.isoformat() + "Z"
        }
        
        # Store the challenge in the database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO challenges (id, action, timestamp, nonce, expires_at) VALUES (?, ?, ?, ?, ?)",
            (challenge_id, action, challenge["timestamp"], nonce, challenge["expires_at"])
        )
        
        # Log the challenge creation
        cursor.execute(
            "INSERT INTO audit_log (id, timestamp, event_type, details) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), now.isoformat() + "Z", "CHALLENGE_CREATED", json.dumps({
                "challenge_id": challenge_id,
                "action": action
            }))
        )
        
        conn.commit()
        conn.close()
        
        # Return the challenge JSON
        print(f"Challenge created for action: {action}")
        print(f"Challenge ID: {challenge_id}")
        print(f"Challenge expires at: {expires_at.isoformat()}Z")
        return challenge
    
    def verify_response(self, challenge_id, response_data):
        """Verify a signed response to a challenge."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get the challenge
        cursor.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,))
        challenge_row = cursor.fetchone()
        
        if not challenge_row:
            print(f"Challenge {challenge_id} not found")
            return False, "Challenge not found"
        
        # Extract challenge data
        challenge_id, action, timestamp, nonce, expires_at, status, _, _ = challenge_row
        
        # Check if challenge has already been used
        if status != "pending":
            print(f"Challenge {challenge_id} has already been {status}")
            return False, f"Challenge has already been {status}"
        
        # Check if challenge has expired
        now = datetime.utcnow()
        expires_at_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if now > expires_at_dt:
            # Update challenge status to expired
            cursor.execute(
                "UPDATE challenges SET status = ? WHERE id = ?",
                ("expired", challenge_id)
            )
            conn.commit()
            print(f"Challenge {challenge_id} has expired")
            return False, "Challenge has expired"
        
        try:
            # Parse the response data
            response_obj = json.loads(response_data)
            response_id = response_obj.get("id")
            response_action = response_obj.get("response")
            signature_b64 = response_obj.get("signature")
            
            # Verify that response ID matches challenge ID
            if response_id != challenge_id:
                raise ValueError("Response ID does not match challenge ID")
            
            # Decode the signature
            signature = base64.b64decode(signature_b64)
            
            # Prepare the message that was signed (should match what client signed)
            message = f"{challenge_id}:{action}:{nonce}:{response_action}".encode()
            
            # Verify the signature
            self.public_key.verify(signature, message)
            
            # If verification succeeds (no exception thrown), update challenge status
            new_status = "approved" if response_action == "approved" else "rejected"
            cursor.execute(
                "UPDATE challenges SET status = ?, response = ?, response_timestamp = ? WHERE id = ?",
                (new_status, response_data, now.isoformat() + "Z", challenge_id)
            )
            
            # Log the verification
            cursor.execute(
                "INSERT INTO audit_log (id, timestamp, event_type, details) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), now.isoformat() + "Z", "RESPONSE_VERIFIED", json.dumps({
                    "challenge_id": challenge_id,
                    "action": action,
                    "result": new_status
                }))
            )
            
            conn.commit()
            print(f"Challenge {challenge_id} has been {new_status}")
            return True, new_status
            
        except Exception as e:
            # Log the verification failure
            cursor.execute(
                "INSERT INTO audit_log (id, timestamp, event_type, details) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), now.isoformat() + "Z", "VERIFICATION_FAILED", json.dumps({
                    "challenge_id": challenge_id,
                    "error": str(e)
                }))
            )
            conn.commit()
            print(f"Verification failed: {e}")
            return False, f"Verification failed: {e}"
        
        finally:
            conn.close()


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python server.py [generate_challenge|verify_response] [args...]")
        sys.exit(1)
    
    server = MfaServer()
    command = sys.argv[1]
    
    if command == "generate_challenge":
        if len(sys.argv) < 3:
            print("Usage: python server.py generate_challenge <action>")
            sys.exit(1)
        action = sys.argv[2]
        challenge = server.generate_challenge(action)
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