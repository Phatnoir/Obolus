#!/bin/bash
# Simple end-to-end test for Obolus

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Create temporary directory for test artifacts
# For Windows compatibility, use a directory in the current path
TEST_DIR="./test_artifacts"
mkdir -p "$TEST_DIR"
echo "Using temporary directory: $TEST_DIR"

# Define paths
CHALLENGE_FILE="$TEST_DIR/challenge.json"
RESPONSE_FILE="$TEST_DIR/response.json"
PRIVATE_KEY="$TEST_DIR/private_key.pem"
PUBLIC_KEY="$TEST_DIR/public_key.pem"

# Clean up on exit (comment this out for debugging)
# trap 'rm -rf "$TEST_DIR"' EXIT

echo "=== Running Obolus Test ==="

# Step 1: Generate keys
echo "[1] Generating keys..."
python tools/keygen.py --output-dir "$TEST_DIR"

# Step 2: Generate challenge
echo "[2] Creating challenge for 'test_action'..."
python tools/challenge-gen.py "test_action" --output "$CHALLENGE_FILE"

# Step 3: Sign challenge
echo "[3] Signing challenge..."
python tools/obolus-sign.py --key "$PRIVATE_KEY" --challenge "$CHALLENGE_FILE" --output "$RESPONSE_FILE"

# Step 4: Verify response
echo "[4] Verifying response..."
if python tools/obolus-verify.py --key "$PUBLIC_KEY" --challenge "$CHALLENGE_FILE" --response "$RESPONSE_FILE"; then
    echo -e "\n✅ SUCCESS: Challenge approved and verified!"
else
    echo -e "\n❌ FAILURE: Verification failed!"
    exit 1
fi

echo -e "\nTest completed successfully!"
echo "Test artifacts are in: $TEST_DIR"
echo "You can examine them for debugging or delete the directory when done."
read -p "Press enter to exit..."