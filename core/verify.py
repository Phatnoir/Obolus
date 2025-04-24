#!/usr/bin/env python3
"""
Obolus core verification module - verify signatures with Ed25519 public keys.
"""

import json
import base64
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Import shared functions
from .shared import parse_challenge, format_message

def load_public_key(key_path):
    """
    Load an Ed25519 public key from a file.
    
    Args:
        key_path (str): Path to the public key file
        
    Returns:
        Ed25519PublicKey: Loaded public key
        
    Raises:
        Exception: If key loading fails
    """
    try:
        with open(key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key
    except Exception as e:
        raise Exception(f"Error loading public key: {e}")

def parse_response(response_data):
    """
    Parse and validate response data.
    
    Args:
        response_data (str or dict): Response data as JSON string or dictionary
        
    Returns:
        dict: Parsed response object
        
    Raises:
        ValueError: If response is invalid or missing required fields
    """
    # Parse JSON if string is provided
    if isinstance(response_data, str):
        try:
            response = json.loads(response_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid response JSON: {e}")
    else:
        response = response_data
    
    # Validate required fields
    required_fields = ["id", "response", "timestamp", "signature"]
    for field in required_fields:
        if field not in response:
            raise ValueError(f"Response missing required field: {field}")
    
    # Validate response action
    if response["response"] not in ["approved", "rejected"]:
        raise ValueError("Response action must be 'approved' or 'rejected'")
    
    return response

def verify_response(challenge_data, response_data, public_key_path):
    """
    Verify a response against a challenge using an Ed25519 public key.
    
    Args:
        challenge_data (str or dict): Challenge data as JSON string or dictionary
        response_data (str or dict): Response data as JSON string or dictionary
        public_key_path (str): Path to the public key file
        
    Returns:
        tuple: (bool, str) - (Success, Status message)
        
    Raises:
        ValueError: If challenge or response is invalid
        Exception: If verification fails due to system errors
    """
    try:
        # Parse and validate challenge and response
        challenge = parse_challenge(challenge_data)
        response = parse_response(response_data)
        
        # Check if response ID matches challenge ID
        if response["id"] != challenge["id"]:
            return False, "Response ID does not match challenge ID"
        
        # Add timestamp validation
        try:
            challenge_time = datetime.fromisoformat(challenge["timestamp"])
            response_time = datetime.fromisoformat(response["timestamp"])
            now = datetime.now(timezone.utc)
    
            # Response should be after challenge was created
            if response_time < challenge_time:
                return False, "Response timestamp predates challenge creation"
        
            # Response shouldn't be from the future (with small tolerance)
            tolerance = timedelta(minutes=5)  # Allow for clock drift
            if response_time > now + tolerance:
                return False, "Response timestamp is from the future"
        except ValueError as e:
            return False, f"Invalid timestamp format: {e}"
        
        # Check if challenge has expired - ENHANCED EXPIRATION HANDLING
        expires_at = datetime.fromisoformat(challenge["expires_at"])
        now = datetime.now(timezone.utc)
        if now > expires_at:
            # Return a specific status code/message for expired challenges
            return False, "EXPIRED"  # Use a consistent code that can be checked
        
        # Load public key
        public_key = load_public_key(public_key_path)
        
        # Format message that was signed
        message = format_message(
            challenge["id"], 
            challenge["action"], 
            challenge["nonce"], 
            response["response"]
        )
        
        # Decode signature
        try:
            signature = base64.b64decode(response["signature"])
        except Exception as e:
            return False, f"Invalid signature encoding: {e}"
        
        # Verify signature
        try:
            public_key.verify(signature, message)
            return True, response["response"]
        except InvalidSignature:
            return False, "Invalid signature"
            
    except Exception as e:
        return False, f"Verification error: {e}"