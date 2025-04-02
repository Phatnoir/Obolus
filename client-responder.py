#!/usr/bin/env python3

import json
import base64
import sys
from datetime import datetime
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class MfaClient:
    def __init__(self, private_key_path="private_key.pem"):
        """Initialize the MFA client with the private key."""
        self.private_key_path = private_key_path
        self.load_private_key()
    
    def load_private_key(self):
        """Load the private key from file."""
        try:
            with open(self.private_key_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
        except Exception as e:
            print(f"Error loading private key: {e}")
            raise
    
    def parse_challenge(self, challenge_data):
        """Parse a challenge from JSON data."""
        try:
            if isinstance(challenge_data, str):
                challenge = json.loads(challenge_data)
            else:
                challenge = challenge_data
                
            # Validate required fields
            required_fields = ["id", "action", "timestamp", "nonce", "expires_at"]
            for field in required_fields:
                if field not in challenge:
                    raise ValueError(f"Challenge missing required field: {field}")
            
            # Check if challenge has expired
            expires_at = datetime.fromisoformat(challenge["expires_at"].replace("Z", "+00:00"))
            now = datetime.utcnow()
            if now > expires_at:
                print(f"Warning: Challenge has expired at {expires_at.isoformat()}")
                
            return challenge
            
        except Exception as e:
            print(f"Error parsing challenge: {e}")
            raise
    
    def display_challenge(self, challenge):
        """Display the challenge in a user-friendly format."""
        print("\n===== MFA CHALLENGE =====")
        print(f"Action: {challenge['action']}")
        print(f"ID: {challenge['id']}")
        
        # Format timestamps for better readability
        created_at = datetime.fromisoformat(challenge["timestamp"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(challenge["expires_at"].replace("Z", "+00:00"))
        
        print(f"Created: {created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        # Calculate time remaining
        now = datetime.utcnow()
        if now < expires_at:
            seconds_remaining = (expires_at - now).total_seconds()
            print(f"Time remaining: {int(seconds_remaining)} seconds")
        else:
            print("Status: EXPIRED")
        
        print("=========================\n")
    
    def sign_response(self, challenge, response_action="approved"):
        """Sign a response to the challenge."""
        # Validate response action
        if response_action not in ["approved", "rejected"]:
            raise ValueError("Response action must be 'approved' or 'rejected'")
        
        # Create the message to sign (format must match what the server expects)
        message = f"{challenge['id']}:{challenge['action']}:{challenge['nonce']}:{response_action}".encode()
        
        # Sign the message
        signature = self.private_key.sign(message)
        
        # Create response object
        response = {
            "id": challenge["id"],
            "response": response_action,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "signature": base64.b64encode(signature).decode("utf-8")
        }
        
        return response


# Command-line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MFA Client for signing challenge responses")
    parser.add_argument("--key", default="private_key.pem", help="Path to private key PEM file")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Parse challenge command
    parse_parser = subparsers.add_parser("parse", help="Parse and display a challenge")
    parse_parser.add_argument("challenge", help="Challenge JSON string or file path")
    
    # Sign response command
    sign_parser = subparsers.add_parser("sign", help="Sign a response to a challenge")
    sign_parser.add_argument("challenge", help="Challenge JSON string or file path")
    sign_parser.add_argument("--action", choices=["approved", "rejected"], default="approved",
                            help="Response action (approved or rejected)")
    sign_parser.add_argument("--output", help="Output file for signed response (default: stdout)")
    
    args = parser.parse_args()
    
    # Initialize client
    client = MfaClient(private_key_path=args.key)
    
    # Handle challenge input (file or direct JSON)
    challenge_data = args.challenge
    if args.command in ["parse", "sign"]:
        try:
            # Check if challenge is a file path
            if args.challenge.endswith('.json'):
                try:
                    with open(args.challenge, 'r') as f:
                        challenge_data = f.read()
                except FileNotFoundError:
                    # If file not found, treat as JSON string
                    pass
            
            challenge = client.parse_challenge(challenge_data)
            client.display_challenge(challenge)
            
            if args.command == "sign":
                response = client.sign_response(challenge, args.action)
                response_json = json.dumps(response, indent=2)
                
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(response_json)
                    print(f"Response saved to {args.output}")
                else:
                    print("Signed Response:")
                    print(response_json)
        
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    elif not args.command:
        parser.print_help()