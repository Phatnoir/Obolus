#!/usr/bin/env python3
"""
Obolus challenge generator - creates challenge objects for Obolus authentication.
"""

import json
import uuid
import base64
import os
import sys  # Add this import
import argparse
from datetime import datetime, timedelta, timezone

def generate_challenge(action, expiry_seconds=60):
    """
    Generate a new Obolus challenge.
    
    Args:
        action (str): Action being authenticated
        expiry_seconds (int): Challenge validity period in seconds
        
    Returns:
        dict: Challenge object
    """
    challenge_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=expiry_seconds)
    nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
    
    challenge = {
        "id": challenge_id,
        "action": action,
        "timestamp": now.isoformat(),
        "nonce": nonce,
        "expires_at": expires_at.isoformat()
    }
    
    return challenge

def main():
    parser = argparse.ArgumentParser(description="Generate Obolus authentication challenges")
    parser.add_argument("action", help="Action being authenticated (e.g., 'login', 'transfer_funds')")
    parser.add_argument("--expiry", type=int, default=60, help="Expiry time in seconds (default: 60)")
    parser.add_argument("--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    try:
        # Generate challenge
        challenge = generate_challenge(args.action, args.expiry)
        challenge_json = json.dumps(challenge, indent=2)
        
        # Output result
        if args.output:
            with open(args.output, 'w') as f:
                f.write(challenge_json)
            print(f"Challenge saved to {args.output}")
        else:
            print(challenge_json)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())