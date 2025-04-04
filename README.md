# Obolus

A portable, lightweight multi-factor authentication protocol designed to work across any transport layer. Obolus separates intent from identity, allowing trusted human approval with cryptographic backing.

## What is Obolus?

Obolus is a minimal protocol for verifying user intent. It provides a "yes/no" gateway that can be embedded in any application or workflow. The name comes from the ancient Greek coin placed in the mouth of the deceased to pay Charon for passage across the river Styx - just as that coin was a token of verification, Obolus provides secure verification of user intent.

## Key Features

- **Lightweight**: Minimal dependencies and simple implementation
- **Protocol-first**: Well-defined protocol that can be implemented in any language
- **Transport-agnostic**: Works over any communication channel (email, SMS, HTTP, etc.)
- **Cryptographically secure**: Uses Ed25519 signatures for verification
- **Embeddable**: Small footprint makes it easy to embed in any application

## Quick Start

1. **Setup**
   ```bash
   # Clone repository
   git clone https://github.com/your-username/obolus.git
   cd obolus
   
   # Generate keys
   python tools/keygen.py --output-dir data/keys
   ```

2. **Generate a challenge**
   ```bash
   python tools/challenge-gen.py "login_request" > challenge.json
   ```

3. **Sign the challenge**
   ```bash
   python tools/obolus-sign.py --key data/keys/private_key.pem --challenge challenge.json > response.json
   ```

4. **Verify the response**
   ```bash
   python tools/obolus-verify.py --key data/keys/public_key.pem --challenge challenge.json --response response.json
   ```

## Project Structure

```
obolus/
├── core/                      # Core protocol implementation
│   ├── __init__.py            # Package exports and imports
│   ├── shared.py              # Common utilities
│   ├── sign.py                # Challenge signing functions
│   └── verify.py              # Response verification functions
├── data/                      # Runtime data (not in repo)
│   ├── db/                    # Database storage (if needed)
│   └── keys/                  # Key storage
├── examples/                  # Example integrations
│   ├── email-example.py       # Email transport example
│   └── iot-example.py         # IoT device example
├── tests/                     # Test scripts
│   └── local-test.sh          # End-to-end test
├── tools/                     # Command line tools
│   ├── challenge-gen.py       # Challenge generator
│   ├── keygen.py              # Key generation utility
│   ├── obolus-sign.py         # Challenge signing tool
│   └── obolus-verify.py       # Response verification tool
├── protocol-spec.md           # Protocol specification
└── README.md                  # This file
```

## Using the Core Library

You can use Obolus as a Python library by importing the core modules:

```python
# Import core functions
from obolus.core import sign_challenge, verify_response

# Generate a challenge (or parse an existing one)
challenge = {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "action": "login_request",
    "timestamp": "2023-04-01T12:34:56Z",
    "nonce": "AAECA/3sd7QkZlMmQ1NWUwOWVk/3d1g=",
    "expires_at": "2023-04-01T12:35:56Z"
}

# Sign a challenge
response = sign_challenge(challenge, "path/to/private_key.pem")

# Verify a response
success, status = verify_response(challenge, response, "path/to/public_key.pem")
```

## Integration Examples

Obolus can be integrated with any system:

### Email-based Verification

```python
# See examples/email-example.py for a full working example
```

### IoT Device Integration

```python
# See examples/iot-example.py for a full working example
```

### Shell Script Integration

```bash
#!/bin/bash
# Generate challenge
CHALLENGE=$(python /path/to/obolus/tools/challenge-gen.py "deploy_to_production")
echo "$CHALLENGE" > /tmp/deploy_challenge.json

# Prompt for approval
echo "Please approve this deployment using your Obolus client"
echo "Challenge saved to /tmp/deploy_challenge.json"

# Wait for response file
while [ ! -f /tmp/deploy_response.json ]; do
    echo "Waiting for response..."
    sleep 5
done

# Verify response
if python /path/to/obolus/tools/obolus-verify.py \
    --key /path/to/public_key.pem \
    --challenge /tmp/deploy_challenge.json \
    --response /tmp/deploy_response.json; then
    echo "Deployment approved! Proceeding..."
    # Run deployment...
else
    echo "Deployment rejected or verification failed!"
    exit 1
fi
```

## License

[Your License]