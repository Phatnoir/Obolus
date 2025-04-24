# Obolus

A portable, lightweight multi-factor authentication protocol designed to work across any transport layer. Obolus separates intent from identity, allowing trusted human approval with cryptographic backing.

## What is Obolus?

Obolus is a minimal protocol for verifying user intent. It provides a "yes/no" gateway that can be embedded in any application or workflow. The name comes from the ancient Greek coin placed in the mouth of the deceased to pay Charon for passage across the river Styx — just as that coin was a token of verification, Obolus provides secure verification of user intent.

## Key Features

- **Lightweight**: Minimal dependencies and simple implementation
- **Protocol-first**: Well-defined protocol that can be implemented in any language
- **Transport-agnostic**: Works over any communication channel (email, SMS, HTTP, etc.)
- **Cryptographically secure**: Uses Ed25519 signatures for verification
- **Embeddable**: Small footprint makes it easy to embed in any application

## Project Structure

```text
obolus/
├── core/                      # Core protocol implementation
├── tools/                     # Command line tools
├── examples/                  # Example integrations
│   ├── backend_example.py     # FastAPI backend demo
│   └── obolus-client.html     # Browser-based client demo
├── tests/                     # Test scripts
├── protocol-spec.md           # Protocol specification
└── README.md                  # This file
```

## Requirements

```bash
# Install dependencies
pip install cryptography fastapi uvicorn pydantic
```

## Quick Start

1. **Setup**

```bash
git clone https://github.com/Phatnoir/Obolus.git
cd Obolus

# Generate keys
python tools/keygen.py --output-dir data/keys
```

2. **Generate a challenge**

```bash
python tools/challenge_gen.py "login_request" > challenge.json
```

3. **Sign the challenge**

```bash
python tools/obolus_sign.py --key data/keys/private_key.pem --challenge challenge.json > response.json
```

4. **Verify the response**

```bash
python tools/obolus_verify.py --key data/keys/public_key.pem --challenge challenge.json --response response.json
```

## Demo Web Interface

A simple interactive demo is available using FastAPI and a static HTML/JavaScript frontend. This shows how Obolus can be used entirely from the browser without any installation. This demo is optional and one of many possible transport implementations.

### Run the Demo

1. **Start the backend API server**

```bash
# Navigate to the root Obolus directory
cd Obolus

# Start the backend server
uvicorn examples.backend_example:app --reload
```

The server will start on http://localhost:8000

2. **Open the client interface**

Open `examples/obolus-client.html` in your web browser.

3. **Try the interactive workflow**

- Generate a keypair in-browser (or use existing keys)
- Request a challenge from the server
- Review the challenge details
- Approve or reject the challenge
- See verification results in real-time

### Demo API Endpoints

- `POST /challenge` - Generate a new challenge
- `POST /verify` - Verify a response against a challenge
- `GET /info` - Check server/public key status

## Using the Core Library

You can use Obolus as a Python library by importing the core modules:

```python
from obolus.core import sign_challenge, verify_response

# Example usage:
challenge = {...}  # A valid challenge object
response = sign_challenge(challenge, "path/to/private_key.pem")
success, status = verify_response(challenge, response, "path/to/public_key.pem")
```

### Base64 Key Support

In addition to file-based key loading, `sign_challenge()` also supports base64-encoded Ed25519 private keys (DER format). This is useful for browser-to-server integrations or serverless environments.

```python
sign_challenge(challenge, base64_private_key_string, is_base64=True)
```

Use this when keys are provided from an external source (e.g. a frontend, secret store, or environment variable).

You can use Obolus as a Python library by importing the core modules:

```python
from obolus.core import sign_challenge, verify_response

# Example usage:
challenge = {...}  # A valid challenge object
response = sign_challenge(challenge, "path/to/private_key.pem")
success, status = verify_response(challenge, response, "path/to/public_key.pem")
```

## Shell Script Integration

Obolus also supports a shell-friendly workflow. This example shows how you might gate a production deployment behind a signed approval:

```bash
#!/bin/bash
CHALLENGE=$(python tools/challenge_gen.py "deploy_to_production")
echo "$CHALLENGE" > /tmp/deploy_challenge.json

echo "Please approve this deployment using your Obolus client"
echo "Challenge saved to /tmp/deploy_challenge.json"

while [ ! -f /tmp/deploy_response.json ]; do
    echo "Waiting for response..."
    sleep 5
done

if python tools/obolus_verify.py \
    --key data/keys/public_key.pem \
    --challenge /tmp/deploy_challenge.json \
    --response /tmp/deploy_response.json; then
    echo "Deployment approved! Proceeding..."
else
    echo "Deployment rejected or verification failed!"
    exit 1
fi
```

## Tests

To verify end-to-end functionality, a test script is provided:

```bash
bash tests/local-test.sh
```

This script generates a challenge, signs it, and verifies the response — demonstrating the full protocol cycle. It will leave behind a temporary directory, `test_artifacts/`, which can be safely removed after testing.

## Protocol Specification

For detailed protocol specifications and implementation guidance, see [protocol-spec.md](protocol-spec.md).

## Design Philosophy

Obolus is designed to support privacy-conscious, intent-driven workflows. While the protocol itself does not provide encryption or anonymity, it avoids identity tracking and enables consent-focused design when paired with secure transport.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
