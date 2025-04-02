#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os

def generate_keys(output_dir='.'):
    """Generate Ed25519 key pair and save them to files."""
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Derive public key
    public_key = private_key.public_key()
    
    # Save private key
    private_key_path = os.path.join(output_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key_path = os.path.join(output_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"✅ Keys generated successfully")
    print(f"   Private key saved to: {private_key_path}")
    print(f"   Public key saved to: {public_key_path}")
    print("\nIMPORTANT: Keep your private key secure and never share it!")

if __name__ == "__main__":
    # You can specify a different output directory if needed
    generate_keys()