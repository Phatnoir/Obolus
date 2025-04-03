#!/bin/bash
set -e

echo "=== Running Local MFA Loopback Test ==="

# Clean up
rm -f challenge.json response.json mfa_challenges.db full_output.txt

# Step 1: Keygen
echo "[1] Generating keys..."
python generate_keys.py

# Step 2: Challenge
echo "[2] Creating challenge for 'test_action'..."
python server-challenge.py generate_challenge "test_action" --json-only > challenge.json

# Step 3: Parse/display
echo "[3] Parsing challenge..."
python client-responder.py parse challenge.json

# Step 4: Sign
echo "[4] Signing challenge..."
python client-responder.py sign challenge.json --action approved --output response.json

# Step 5: Verify
echo "[5] Verifying response..."
CHALLENGE_ID=$(jq -r .id challenge.json)
RESPONSE=$(cat response.json)

VERIFY_OUTPUT=$(python server-challenge.py verify_response "$CHALLENGE_ID" "$RESPONSE")

if echo "$VERIFY_OUTPUT" | grep -q "has been approved"; then
    echo -e "\n✅ SUCCESS: Challenge approved and verified!"
else
    echo -e "\n❌ FAILURE: Verification failed!"
    echo "$VERIFY_OUTPUT"
    exit 1
fi
