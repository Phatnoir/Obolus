# Obolus Protocol Specification

## Overview

Obolus is a portable, lightweight multi-factor authentication protocol designed to verify user intent across any transport layer. It uses asymmetric cryptography (Ed25519) to implement a challenge-response mechanism that can be embedded in any application.

## Protocol Messages

### 1. Challenge

A challenge is a JSON object with the following fields:

```json
{
  "id": "unique-challenge-id",
  "action": "description-of-requested-action",
  "timestamp": "ISO-8601-timestamp",
  "nonce": "base64-encoded-random-bytes",
  "expires_at": "ISO-8601-timestamp-for-expiration"
}
```

Fields:
- `id`: A unique identifier for the challenge (UUID v4 recommended).
- `action`: A human-readable description of the action being authenticated.
- `timestamp`: When the challenge was created (ISO-8601 format with timezone).
- `nonce`: Random bytes encoded in base64 (minimum 16 bytes recommended).
- `expires_at`: When the challenge expires (ISO-8601 format with timezone).

### 2. Response

A response is a JSON object with the following fields:

```json
{
  "id": "same-challenge-id",
  "response": "approved|rejected",
  "timestamp": "ISO-8601-timestamp",
  "signature": "base64-encoded-signature"
}
```

Fields:
- `id`: The ID of the challenge being responded to.
- `response`: Either "approved" or "rejected".
- `timestamp`: When the response was created (ISO-8601 format with timezone).
- `signature`: Ed25519 signature encoded in base64.

## Signature Generation

The signature is an Ed25519 signature of a string with the following format:
```
{challenge_id}:{action}:{nonce}:{response}
```

Where:
- `challenge_id` is the ID from the challenge
- `action` is the action string from the challenge
- `nonce` is the nonce string from the challenge
- `response` is either "approved" or "rejected"

## Verification Process

1. Server generates and sends a challenge to the client.
2. Client displays the challenge to the user.
3. User approves or rejects the action.
4. Client signs the response and sends it back to the server.
5. Server verifies the signature using the client's public key.

## Implementation Requirements

An Obolus-compatible implementation MUST:

1. Support Ed25519 signatures
2. Validate all fields in challenges and responses
3. Check expiration time before verifying signatures
4. Include the challenge ID, action, and nonce in the signed message
5. Encode binary data using base64

## Integration

Obolus can be integrated into any system using one of these approaches:

1. **CLI Tools**: Use the command-line tools for signing and verification
   ```bash
   # Generate a challenge
   ./obolus/tools/challenge-gen.py "fund_transfer" > challenge.json
   
   # Sign a challenge
   ./obolus/tools/obolus-sign.py --key private_key.pem --challenge challenge.json > response.json
   
   # Verify a response
   ./obolus/tools/obolus-verify.py --key public_key.pem --challenge challenge.json --response response.json
   ```

2. **Core Library Functions**: Import the core modules in your Python code
   ```python
   from obolus.core.sign import sign_challenge
   from obolus.core.verify import verify_response
   
   # Generate and sign a challenge
   challenge = generate_challenge("fund_transfer")
   response = sign_challenge(challenge, "private_key.pem")
   
   # Verify a response
   success, status = verify_response(challenge, response, "public_key.pem")
   ```

3. **Custom Implementation**: Implement the protocol in any language following this specification