#!/usr/bin/env python3
"""
Obolus IoT Device Example

This example shows how Obolus can be used to secure actions on IoT devices:
1. A user requests an action on an IoT device via a REST API
2. The device generates a challenge and returns it
3. The user signs the challenge with their Obolus client
4. The device verifies the signature before executing the action

This is a simplified example using Flask to simulate an IoT device API.
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify

# Add parent directory to path to import Obolus modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from tools.challenge_gen import generate_challenge
    # We'll use the CLI verify tool for simplicity
except ImportError:
    print("Could not import Obolus modules. Running in standalone mode.")
    
# Simple function to generate a challenge if we can't import the module
def standalone_generate_challenge(action, expiry=60):
    """Generate challenge using the CLI tool"""
    obolus_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    cmd = [sys.executable, os.path.join(obolus_dir, "tools", "challenge-gen.py"), 
           action, "--expiry", str(expiry)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

# Simple function to verify response if we can't import the module
def standalone_verify_response(challenge, response, public_key):
    """Verify response using the CLI tool"""
    # Write challenge and response to temporary files
    temp_dir = os.path.join(os.getcwd(), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    
    challenge_file = os.path.join(temp_dir, f"challenge_{challenge['id']}.json")
    response_file = os.path.join(temp_dir, f"response_{challenge['id']}.json")
    
    with open(challenge_file, "w") as f:
        json.dump(challenge, f)
    
    with open(response_file, "w") as f:
        json.dump(response, f)
    
    obolus_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    cmd = [sys.executable, os.path.join(obolus_dir, "tools", "obolus-verify.py"),
           "--key", public_key,
           "--challenge", challenge_file,
           "--response", response_file]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout

# Simulated IoT device actions
class IoTDevice:
    def __init__(self, device_id, public_key):
        self.device_id = device_id
        self.public_key = public_key
        self.pending_challenges = {}  # Store challenges by ID
        
        # Simulated device state
        self.state = {
            "power": "off",
            "temperature": 21,
            "lock": "locked"
        }
        
        # Define actions that require authentication
        self.secure_actions = {
            "set_power": self._set_power,
            "set_temperature": self._set_temperature,
            "unlock_door": self._unlock_door
        }
    
    def _set_power(self, value):
        if value not in ["on", "off"]:
            return False, "Invalid power state. Must be 'on' or 'off'."
        self.state["power"] = value
        return True, f"Power set to {value}"
    
    def _set_temperature(self, value):
        try:
            temp = int(value)
            if temp < 10 or temp > 30:
                return False, "Temperature must be between 10 and 30."
            self.state["temperature"] = temp
            return True, f"Temperature set to {temp}"
        except ValueError:
            return False, "Invalid temperature value."
    
    def _unlock_door(self, value):
        if value != "true":
            return False, "Invalid unlock parameter. Must be 'true'."
        self.state["lock"] = "unlocked"
        # Auto-lock after a while would be implemented in a real device
        return True, "Door unlocked"
    
    def get_state(self):
        return self.state
    
    def request_action(self, action, param):
        """Generate a challenge for a specific action"""
        if action not in self.secure_actions:
            return None, f"Unknown action: {action}"
        
        action_desc = f"{action}({param}) on device {self.device_id}"
        
        try:
            # Use imported function if available, otherwise use standalone
            if 'generate_challenge' in globals():
                challenge = generate_challenge(action_desc)
            else:
                challenge = standalone_generate_challenge(action_desc)
            
            # Store challenge for later verification
            self.pending_challenges[challenge["id"]] = {
                "challenge": challenge,
                "action": action,
                "param": param,
                "created_at": datetime.now().isoformat()
            }
            
            return challenge, None
        except Exception as e:
            return None, f"Error generating challenge: {e}"
    
    def process_response(self, response_data):
        """Process a signed response and execute the action if valid"""
        try:
            response = json.loads(response_data) if isinstance(response_data, str) else response_data
            challenge_id = response.get("id")
            
            if challenge_id not in self.pending_challenges:
                return False, "Challenge not found or already processed"
            
            pending = self.pending_challenges[challenge_id]
            challenge = pending["challenge"]
            action = pending["action"]
            param = pending["param"]
            
            # Verify the response
            if 'verify_response' in globals():
                success, message = verify_response(challenge, response, self.public_key)
            else:
                success, message = standalone_verify_response(challenge, response, self.public_key)
            
            if not success:
                return False, f"Verification failed: {message}"
            
            # Only execute the action if the response was "approved"
            if response.get("response") != "approved":
                return False, "Action was rejected by the user"
            
            # Execute the action
            action_func = self.secure_actions[action]
            success, result = action_func(param)
            
            # Remove the pending challenge
            del self.pending_challenges[challenge_id]
            
            return success, result
        except Exception as e:
            return False, f"Error processing response: {e}"

# Set up Flask application
app = Flask(__name__)
device = None  # Will be initialized in main()

@app.route('/state', methods=['GET'])
def get_state():
    """Get the current device state"""
    return jsonify(device.get_state())

@app.route('/action/<action>', methods=['POST'])
def request_action(action):
    """Request an action and get a challenge"""
    param = request.json.get('param', '')
    challenge, error = device.request_action(action, param)
    
    if error:
        return jsonify({"error": error}), 400
    
    return jsonify({"challenge": challenge})

@app.route('/verify', methods=['POST'])
def verify_response():
    """Submit a signed response to execute an action"""
    response_data = request.json
    
    if not response_data:
        return jsonify({"error": "No response data provided"}), 400
    
    success, result = device.process_response(response_data)
    
    if not success:
        return jsonify({"error": result}), 400
    
    return jsonify({"success": True, "result": result})

def main():
    parser = argparse.ArgumentParser(description="Obolus IoT Device Example")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the API server on")
    parser.add_argument("--device-id", default="device001", help="Device ID")
    parser.add_argument("--public-key", required=True, help="Path to the public key file")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    
    args = parser.parse_args()
    
    global device
    device = IoTDevice(args.device_id, args.public_key)
    
    print(f"Starting IoT device simulator (ID: {args.device_id})")
    print(f"API available at http://localhost:{args.port}")
    print("Available actions:")
    print("  - set_power (param: 'on' or 'off')")
    print("  - set_temperature (param: 10-30)")
    print("  - unlock_door (param: 'true')")
    
    app.run(host='0.0.0.0', port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()