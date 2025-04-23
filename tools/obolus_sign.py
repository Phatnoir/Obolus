#!/usr/bin/env python3
"""
Obolus Sign - Command-line tool for signing Obolus challenges.

Usage:
  obolus-sign --key PRIVATE_KEY_FILE --challenge CHALLENGE_FILE [--action approved|rejected] [--output OUTPUT_FILE]
  obolus-sign --help

Options:
  --key PRIVATE_KEY_FILE      Path to Ed25519 private key file
  --challenge CHALLENGE_FILE  Path to challenge JSON file
  --action ACTION             Response action (approved or rejected) [default: approved]
  --output OUTPUT_FILE        Output file for signed response [default: stdout]
  --help                      Show this help message and exit
"""

import sys
import os
import json
import argparse

# Add parent directory to path so we can import core modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from core.sign import sign_challenge, sign_challenge_to_json
    from core.shared import display_challenge, parse_challenge
except ImportError:
    print("Error: Could not import core modules.")
    print("Make sure this script is run from the obolus directory or the core modules are in your Python path.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Obolus Sign - Command-line tool for signing Obolus challenges")
    parser.add_argument("--key", required=True, help="Path to Ed25519 private key file")
    parser.add_argument("--challenge", required=True, help="Path to challenge JSON file")
    parser.add_argument("--action", choices=["approved", "rejected"], default="approved", 
                        help="Response action (approved or rejected)")
    parser.add_argument("--output", help="Output file for signed response (default: stdout)")
    
    # Parse arguments
    args = parser.parse_args()
    
    try:
        # Read challenge file
        with open(args.challenge, 'r') as f:
            challenge_data = f.read()
        
        # Display challenge
        challenge = parse_challenge(challenge_data)
        display_challenge(challenge)
        
        # Confirm action if interactive
        if sys.stdin.isatty() and sys.stdout.isatty():
            confirm = input(f"Do you want to {args.action} this challenge? [y/N] ")
            if confirm.lower() not in ['y', 'yes']:
                print("Aborted.")
                return
        
        # Sign challenge
        response_json = sign_challenge_to_json(challenge_data, args.key, args.action)
        
        # Output response
        if args.output:
            with open(args.output, 'w') as f:
                f.write(response_json)
            print(f"Response saved to {args.output}")
        else:
            print(response_json)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()