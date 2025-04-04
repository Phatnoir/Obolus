#!/usr/bin/env python3
"""
Obolus core signing module - sign challenges with Ed25519 private keys.
"""

import json
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Import shared functions
from .shared import parse_challenge, format_message, create_response

def load_private_key(key_path):
    """
    Load an Ed25519 private key from a file.
    
    Args:
        key_path (str): Path to the private key file
        
    Returns:
        Ed25519PrivateKey: Loaded private key
        
    Raises:
        Exception: If key loading fails
    """
    try:
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        return private_key
    except Exception as e:
        raise Exception(f"Error loading private key: {e}")

def sign_challenge(challenge_data, private_key_path, response_action="approved"):
    """
    Sign a challenge with an Ed25519 private key.
    
    Args:
        challenge_data (str or dict): Challenge data as JSON string or dictionary
        private_key_path (str): Path to the private key file
        response_action (str): Response action ('approved' or 'rejected')
        
    Returns:
        dict: Signed response object
        
    Raises:
        ValueError: If challenge is invalid or response action is invalid
        Exception: If signing fails
    """
    # Parse and validate challenge
    challenge = parse_challenge(challenge_data)
    
    # Load private key
    private_key = load_private_key(private_key_path)
    
    # Format message and sign
    message = format_message(
        challenge["id"], 
        challenge["action"], 
        challenge["nonce"], 
        response_action
    )
    signature = private_key.sign(message)
    
    # Create response
    return create_response(challenge["id"], response_action, signature)

def sign_challenge_to_json(challenge_data, private_key_path, response_action="approved"):
    """
    Sign a challenge and return the response as a JSON string.
    
    Args:
        challenge_data (str or dict): Challenge data as JSON string or dictionary
        private_key_path (str): Path to the private key file
        response_action (str): Response action ('approved' or 'rejected')
        
    Returns:
        str: JSON string of the signed response
        
    Raises:
        ValueError: If challenge is invalid or response action is invalid
        Exception: If signing fails
    """
    response = sign_challenge(challenge_data, private_key_path, response_action)
    return json.dumps(response, indent=2)