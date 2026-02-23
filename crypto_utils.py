"""
Cryptography utilities for Secure File Storage.
Uses AES-256-GCM for file encryption and RSA-2048 for DEK encryption.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# AES key size: 256 bits = 32 bytes
AES_KEY_SIZE = 32
# GCM nonce size: 96 bits = 12 bytes (recommended)
GCM_NONCE_SIZE = 12
# RSA key size
RSA_KEY_SIZE = 2048


def ensure_dirs(keys_dir, storage_dir):
    """Ensure keys and storage directories exist."""
    Path(keys_dir).mkdir(parents=True, exist_ok=True)
    Path(storage_dir).mkdir(parents=True, exist_ok=True)


def generate_rsa_keys(version, keys_dir):
    """
    Generate RSA 2048 key pair for given version.
    Saves public and private keys to keys directory.
    Keys stored as: private_v{N}.pem, public_v{N}.pem
    """
    Path(keys_dir).mkdir(parents=True, exist_ok=True)
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    
    # Generate public key from private
    public_key = private_key.public_key()
    
    # Serialize and save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_path = os.path.join(keys_dir, f'private_v{version}.pem')
    with open(private_path, 'wb') as f:
        f.write(private_pem)
    
    # Serialize and save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_path = os.path.join(keys_dir, f'public_v{version}.pem')
    with open(public_path, 'wb') as f:
        f.write(public_pem)
    
    return private_path, public_path


def load_rsa_public_key(version, keys_dir):
    """Load RSA public key for given version."""
    public_path = os.path.join(keys_dir, f'public_v{version}.pem')
    if not os.path.exists(public_path):
        raise FileNotFoundError(f"Public key v{version} not found")
    
    with open(public_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def load_rsa_private_key(version, keys_dir):
    """Load RSA private key for given version."""
    private_path = os.path.join(keys_dir, f'private_v{version}.pem')
    if not os.path.exists(private_path):
        raise FileNotFoundError(f"Private key v{version} not found")
    
    with open(private_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def encrypt_file_aes(file_bytes, key):
    """
    Encrypt file using AES-256-GCM.
    Returns (ciphertext, nonce) - nonce must be stored with file for decryption.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(GCM_NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    
    return ciphertext, nonce


def decrypt_file_aes(ciphertext, key, nonce):
    """
    Decrypt file using AES-256-GCM.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_dek_rsa(dek, public_key):
    """
    Encrypt Data Encryption Key (DEK) using RSA public key.
    DEK is 32 bytes (AES-256 key).
    """
    ciphertext = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_dek_rsa(encrypted_dek, private_key):
    """
    Decrypt DEK using RSA private key.
    """
    dek = private_key.decrypt(
        encrypted_dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return dek


def generate_dek():
    """Generate random 256-bit AES key for file encryption."""
    return os.urandom(AES_KEY_SIZE)
