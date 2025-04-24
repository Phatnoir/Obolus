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
        
def load_private_key_from_base64(base64_key):
    """
    Load an Ed25519 private key from a base64 string.
    
    Args:
        base64_key (str): Base64-encoded private key
        
    Returns:
        Ed25519PrivateKey: Loaded private key
        
    Raises:
        Exception: If key loading fails
    """
    try:
        # Add validation for empty or obviously invalid input
        if not base64_key or len(base64_key.strip()) == 0:
            raise ValueError("Empty base64 key provided")
            
        # Simple pattern check for base64 string (optional)
        import re
        if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', base64_key.strip()):
            raise ValueError("Input does not appear to be valid base64")
            
        key_bytes = base64.b64decode(base64_key)
        private_key = serialization.load_der_private_key(
            key_bytes,
            password=None
        )
        return private_key
    except Exception as e:
        raise Exception(f"Error loading private key from base64: {e}")

def sign_challenge(challenge_data, private_key_source, response_action="approved", is_base64=False):
    """
    Sign a challenge with an Ed25519 private key.
    
    Args:
        challenge_data (str or dict): Challenge data as JSON string or dictionary
        private_key_source (str): Path to private key file or base64-encoded key
        response_action (str): Response action ('approved' or 'rejected')
        is_base64 (bool): Whether private_key_source is a base64 string
        
    Returns:
        dict: Signed response object
        
    Raises:
        ValueError: If challenge is invalid or response action is invalid
        Exception: If signing fails
    """
    # Parse and validate challenge
    challenge = parse_challenge(challenge_data)
    
    # Load private key
    if is_base64:
        private_key = load_private_key_from_base64(private_key_source)
    else:
        private_key = load_private_key(private_key_source)
    
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

def sign_challenge_to_json(challenge_data, private_key_source, response_action="approved", is_base64=False):
    """
    Sign a challenge and return the response as a JSON string.
    
    Args:
        challenge_data (str or dict): Challenge data as JSON string or dictionary
        private_key_source (str): Path to private key file or base64-encoded key
        response_action (str): Response action ('approved' or 'rejected')
        is_base64 (bool): Whether private_key_source is a base64 string
        
    Returns:
        str: JSON string of the signed response
        
    Raises:
        ValueError: If challenge is invalid or response action is invalid
        Exception: If signing fails
    """
    response = sign_challenge(challenge_data, private_key_source, response_action, is_base64)
    return json.dumps(response, indent=2)