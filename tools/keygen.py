#!/usr/bin/env python3
"""
Obolus key generation tool - creates Ed25519 keypairs for Obolus authentication.
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os
import sys  # Add this import
import argparse

def generate_keys(output_dir=None, private_key_name="private_key.pem", public_key_name="public_key.pem"):
    """
    Generate Ed25519 key pair for Obolus and save to files.
    
    Args:
        output_dir (str): Directory to save keys (default: current directory)
        private_key_name (str): Filename for private key
        public_key_name (str): Filename for public key
        
    Returns:
        tuple: (private_key_path, public_key_path)
    """
    # Set default output directory if not specified
    if output_dir is None:
        output_dir = os.getcwd()
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    # Derive public key
    public_key = private_key.public_key()
    
    # Create paths
    private_key_path = os.path.join(output_dir, private_key_name)
    public_key_path = os.path.join(output_dir, public_key_name)
    
    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key_path, public_key_path

def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 key pair for Obolus authentication")
    parser.add_argument("--output-dir", help="Directory to save key files")
    parser.add_argument("--private-key", default="private_key.pem", help="Filename for private key")
    parser.add_argument("--public-key", default="public_key.pem", help="Filename for public key")
    
    args = parser.parse_args()
    
    try:
        private_key_path, public_key_path = generate_keys(
            output_dir=args.output_dir,
            private_key_name=args.private_key,
            public_key_name=args.public_key
        )
        
        print(f"✅ Keys generated successfully")
        print(f"   Private key saved to: {private_key_path}")
        print(f"   Public key saved to: {public_key_path}")
        print("\nIMPORTANT: Keep your private key secure and never share it!")
        
    except Exception as e:
        print(f"Error generating keys: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())