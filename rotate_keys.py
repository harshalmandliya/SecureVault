"""
Key Rotation for SecureVault.
Generates new RSA key pair, re-encrypts all DEKs with new public key.
Does NOT re-encrypt actual file data - only the Data Encryption Keys.
Uses key_metadata table for version; logs to rotation_logs.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import KEYS_DIR, STORAGE_DIR
from db import (
    init_database,
    get_all_files_for_rotation,
    update_file_dek,
    get_key_metadata,
    update_key_version,
    add_rotation_log,
)
from crypto_utils import (
    ensure_dirs,
    generate_rsa_keys,
    load_rsa_public_key,
    load_rsa_private_key,
    decrypt_dek_rsa,
    encrypt_dek_rsa,
)


def get_current_version():
    """Get current master key version from DB."""
    init_database()
    meta = get_key_metadata()
    return meta['current_version'] if meta else 1


def ensure_keys_exist(version):
    """Generate RSA keys if they don't exist for given version."""
    private_path = os.path.join(KEYS_DIR, f'private_v{version}.pem')
    if not os.path.exists(private_path):
        generate_rsa_keys(version, KEYS_DIR)


def perform_rotation():
    """
    Perform full key rotation:
    1. Generate new RSA key pair (version N+1)
    2. For each file: decrypt DEK with old key, re-encrypt with new key
    3. Update database with new encrypted DEK and master_key_version
    4. Update key_metadata and add rotation_log
    """
    ensure_dirs(KEYS_DIR, STORAGE_DIR)
    init_database()

    meta = get_key_metadata()
    old_version = meta['current_version'] if meta else 1
    ensure_keys_exist(old_version)

    new_version = old_version + 1

    print(f"Rotating keys: v{old_version} -> v{new_version}")

    # Step 1: Generate new RSA key pair
    generate_rsa_keys(new_version, KEYS_DIR)
    print(f"Generated new key pair v{new_version}")

    # Load old private key and new public key
    old_private_key = load_rsa_private_key(old_version, KEYS_DIR)
    new_public_key = load_rsa_public_key(new_version, KEYS_DIR)

    # Step 2 & 3: Re-encrypt all DEKs
    files = get_all_files_for_rotation()
    count = 0

    for file_record in files:
        file_id = file_record['id']
        encrypted_dek = bytes(file_record['encrypted_dek'])

        dek = decrypt_dek_rsa(encrypted_dek, old_private_key)
        new_encrypted_dek = encrypt_dek_rsa(dek, new_public_key)
        update_file_dek(file_id, new_encrypted_dek, new_version)
        count += 1

    # Step 4: Update key_metadata and log
    update_key_version(new_version)
    add_rotation_log(old_version, new_version)

    print(f"Rotation complete. Updated {count} file(s). Current version: v{new_version}")
    return new_version


def main():
    """Standalone execution for cron/scheduled jobs."""
    try:
        perform_rotation()
        print("Key rotation successful.")
    except Exception as e:
        print(f"Key rotation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
