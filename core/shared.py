#!/usr/bin/env python3
"""
Obolus core shared functions - common utilities for signing and verification.
"""

import json
import base64
import os
from datetime import datetime, timezone

def parse_challenge(challenge_data):
    """
    Parse and validate challenge data.
    
    Args:
        challenge_data (str or dict): Challenge data as JSON string or dictionary
        
    Returns:
        dict: Parsed challenge object
        
    Raises:
        ValueError: If challenge is invalid or missing required fields
    """
    # Parse JSON if string is provided
    if isinstance(challenge_data, str):
        try:
            challenge = json.loads(challenge_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid challenge JSON: {e}")
    else:
        challenge = challenge_data
    
    # Validate required fields
    required_fields = ["id", "action", "timestamp", "nonce", "expires_at"]
    for field in required_fields:
        if field not in challenge:
            raise ValueError(f"Challenge missing required field: {field}")
    
    # Check expiration
    try:
        expires_at = datetime.fromisoformat(challenge["expires_at"])
        now = datetime.now(timezone.utc)
        if now > expires_at:
            print(f"Warning: Challenge has expired at {expires_at.isoformat()}")
    except ValueError as e:
        raise ValueError(f"Invalid expires_at format: {e}")
    
    return challenge

def format_message(challenge_id, action, nonce, response_action):
    """
    Format the message string to be signed.
    
    Args:
        challenge_id (str): Challenge ID
        action (str): Action being authenticated
        nonce (str): Challenge nonce
        response_action (str): Response action ('approved' or 'rejected')
        
    Returns:
        bytes: Encoded message ready for signing
    """
    if response_action not in ["approved", "rejected"]:
        raise ValueError("Response action must be 'approved' or 'rejected'")
    
    message = f"{challenge_id}:{action}:{nonce}:{response_action}"
    return message.encode()

def create_response(challenge_id, response_action, signature):
    """
    Create a response object.
    
    Args:
        challenge_id (str): Challenge ID
        response_action (str): Response action ('approved' or 'rejected')
        signature (bytes): Raw signature bytes
        
    Returns:
        dict: Response object
    """
    return {
        "id": challenge_id,
        "response": response_action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signature": base64.b64encode(signature).decode("utf-8")
    }

def display_challenge(challenge):
    """
    Display challenge information in a human-readable format.
    
    Args:
        challenge (dict): Challenge object
    """
    print("\n===== OBOLUS CHALLENGE =====")
    print(f"Action: {challenge['action']}")
    print(f"ID: {challenge['id']}")

    created_at = datetime.fromisoformat(challenge["timestamp"])
    expires_at = datetime.fromisoformat(challenge["expires_at"])

    print(f"Created: {created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    now = datetime.now(timezone.utc)
    if now < expires_at:
        seconds_remaining = (expires_at - now).total_seconds()
        print(f"Time remaining: {int(seconds_remaining)} seconds")
    else:
        print("Status: EXPIRED")

    print("=========================\n")