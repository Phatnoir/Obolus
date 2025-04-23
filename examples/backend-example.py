#!/usr/bin/env python3
"""
Obolus Backend Example

A simple FastAPI implementation showcasing how to use Obolus for challenge-response authentication.
This provides two main endpoints:
- POST /challenge - Generate a new challenge
- POST /verify - Verify a response against a challenge
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import sys
import json
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone

# Add parent directory to path so we can import core modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import obolus modules
try:
    from core.shared import parse_challenge
    from tools.challenge_gen import generate_challenge
    from core.verify import verify_response
except ImportError:
    print("Error: Could not import Obolus modules.")
    print("Make sure this script is run from the Obolus directory.")
    sys.exit(1)

app = FastAPI(title="Obolus Demo API")

# Add CORS middleware to allow browser requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For demo purposes only, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ChallengeRequest(BaseModel):
    action: str
    expiry_seconds: int = 60

class VerifyRequest(BaseModel):
    challenge: Dict[str, Any]
    response: Dict[str, Any]

# Endpoint to generate a challenge
@app.post("/challenge")
async def create_challenge(request: ChallengeRequest):
    """
    Generate a new Obolus challenge for the specified action.
    """
    try:
        challenge = generate_challenge(request.action, request.expiry_seconds)
        return challenge
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating challenge: {str(e)}")

# Endpoint to verify a response
@app.post("/verify")
async def verify_challenge_response(request: VerifyRequest):
    """
    Verify a signed response against a challenge.
    Returns whether verification was successful and the status.
    """
    try:
        # Convert objects to JSON strings
        challenge_json = json.dumps(request.challenge)
        response_json = json.dumps(request.response)
        
        # Load public key from environment variable or default location
        public_key_path = os.getenv("OBOLUS_PUBLIC_KEY", "data/keys/public_key.pem")
        if not os.path.exists(public_key_path):
            raise HTTPException(
                status_code=500, 
                detail=f"Public key not found at {public_key_path}. Set OBOLUS_PUBLIC_KEY environment variable or generate keys."
            )
        
        # Verify response
        success, status = verify_response(challenge_json, response_json, public_key_path)
        
        return {
            "verified": success,
            "status": status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verifying response: {str(e)}")

# Endpoint to get server info
@app.get("/info")
async def get_server_info():
    """
    Get information about this Obolus server.
    """
    public_key_path = os.getenv("OBOLUS_PUBLIC_KEY", "data/keys/public_key.pem")
    
    return {
        "name": "Obolus Demo Server",
        "version": "1.0.0",
        "public_key_path": public_key_path,
        "public_key_exists": os.path.exists(public_key_path),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    print("Starting Obolus Demo API...")
    print("Make sure you've generated keys with: python tools/keygen.py --output-dir data/keys")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)