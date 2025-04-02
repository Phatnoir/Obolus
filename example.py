#!/bin/bash
# Example workflow for using the MFA system

echo "=== MFA System Demonstration ==="
echo ""

# Step 1: Generate keys (skip if already done)
echo "1. Generating Ed25519 key pair..."
python generate_keys.py
echo ""

# Step 2: Generate a challenge from the server for an action
echo "2. Server generates a challenge for action 'unlock_safe'..."
CHALLENGE=$(python server-challenge.py generate_challenge "unlock_safe")
CHALLENGE_JSON=$(echo "$CHALLENGE" | grep -A 999 "Challenge JSON:" | tail -n +2)
echo "$CHALLENGE_JSON" > challenge.json
echo "Challenge saved to challenge.json"
echo ""

# Step 3: Client receives and displays the challenge
echo "3. Client receives and displays the challenge..."
python client-responder.py parse challenge.json
echo ""

# Step 4: User approves the challenge (this would normally prompt for confirmation)
echo "4. User approves the challenge..."
python client-responder.py sign challenge.json --action approved --output response.json
echo ""

# Step 5: Server verifies the response
echo "5. Server verifies the response..."
CHALLENGE_ID=$(cat challenge.json | python -c "import sys, json; print(json.load(sys.stdin)['id'])")
RESPONSE=$(cat response.json)
python server-challenge.py verify_response "$CHALLENGE_ID" "$RESPONSE"
echo ""

echo "=== Demonstration Complete ==="