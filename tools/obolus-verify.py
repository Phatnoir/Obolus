#!/usr/bin/env python3
"""
Obolus Verify - Command-line tool for verifying Obolus challenge responses.

Usage:
  obolus-verify --key PUBLIC_KEY_FILE --challenge CHALLENGE_FILE --response RESPONSE_FILE
  obolus-verify --help

Options:
  --key PUBLIC_KEY_FILE       Path to Ed25519 public key file
  --challenge CHALLENGE_FILE  Path to challenge JSON file
  --response RESPONSE_FILE    Path to response JSON file
  --help                      Show this help message and exit
"""

import sys
import os
import json
import argparse

# Add parent directory to path so we can import core modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from core.verify import verify_response
    from core.shared import display_challenge, parse_challenge
except ImportError:
    print("Error: Could not import core modules.")
    print("Make sure this script is run from the obolus directory or the core modules are in your Python path.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Obolus Verify - Command-line tool for verifying Obolus challenge responses")
    parser.add_argument("--key", required=True, help="Path to Ed25519 public key file")
    parser.add_argument("--challenge", required=True, help="Path to challenge JSON file")
    parser.add_argument("--response", required=True, help="Path to response JSON file")
    
    # Parse arguments
    args = parser.parse_args()
    
    try:
        # Read challenge and response files
        with open(args.challenge, 'r') as f:
            challenge_data = f.read()
        
        with open(args.response, 'r') as f:
            response_data = f.read()
        
        # Display challenge
        challenge = parse_challenge(challenge_data)
        display_challenge(challenge)
        
        # Verify response
        success, status = verify_response(challenge_data, response_data, args.key)
        
        # Output result
        if success:
            print(f"✅ Verification successful! The challenge was {status}.")
            sys.exit(0)
        else:
            print(f"❌ Verification failed: {status}")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()