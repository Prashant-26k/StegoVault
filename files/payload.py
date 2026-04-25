# ============================================================
# payload.py - Secret File Preparation and Recovery
# ============================================================

# --- IMPORTS ---

import os
import zlib
import struct
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --- CONSTANTS ---

MAGIC_BYTES = b'STEG'

HEADER_SIZE = 4 + 4 + 16 + 12 + 255


# ============================================================
# FUNCTION 1 - derive_key()
# ============================================================

def derive_key(password, salt):
    """
    Converts a human password into a fixed-size encryption key.

    Parameters:
        password : string  - the user's password e.g. "mysecret"
        salt     : bytes   - 16 random bytes generated fresh each time

    Returns:
        key      : bytes   - exactly 32 bytes, ready for AES-256
    """

    password_bytes = password.encode('utf-8')

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        100000,
        dklen=32
    )

    return key


# NOTE: Legacy reference implementation — not used by main.py.
# main.py uses its own build_payload() function.
# Kept for documentation and presentation purposes.
def prepare_payload(secret_file_path, password):

    """
    Takes any secret file and prepares it for hiding.

    Steps:
    1. Read the file as raw bytes
    2. Compress with zlib
    3. Generate random salt
    4. Derive encryption key from password + salt
    5. Encrypt with AES-256-GCM
    6. Build header: MAGIC + salt + filename + sizes
    7. Return final blob ready to hide

    Parameters:
        secret_file_path : path to any file you want to hide
        password         : string password

    Returns:
        bytes object ready to be embedded in image
    """

    print(f"  Reading file: {secret_file_path}")

    # ── Step 1: Read the secret file ──────────────────────
    with open(secret_file_path, 'rb') as f:
        raw_bytes = f.read()

    original_size = len(raw_bytes)
    print(f"  Original file size : {original_size:,} bytes")

    # ── Step 2: Compress ──────────────────────────────────
    compressed = zlib.compress(raw_bytes, level=6)
    compressed_size = len(compressed)

    ratio = (1 - compressed_size / original_size) * 100
    print(f"  Compressed size    : {compressed_size:,} bytes "
          f"({ratio:.1f}% smaller)")

    # ── Step 3: Generate random salt ──────────────────────
    salt = secrets.token_bytes(16)

    # ── Step 4: Derive encryption key ─────────────────────
    key = derive_key(password, salt)

    # ── Step 5: Encrypt ───────────────────────────────────
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, compressed, None)

    print(f"  Encrypted size     : {len(encrypted):,} bytes")

    # ── Step 6: Build the header ──────────────────────────
    filename = os.path.basename(secret_file_path)
    filename_bytes = filename.encode('utf-8')
    filename_length = len(filename_bytes)

    original_size_bytes = original_size.to_bytes(4, 'big')
    filename_length_bytes = filename_length.to_bytes(4, 'big')

    final_payload = (
        MAGIC_BYTES                 +
        salt                   +
        nonce                  +
        original_size_bytes    +
        filename_length_bytes  +
        filename_bytes         +
        encrypted
    )

    total_size = len(final_payload)
    print(f"  Final payload size : {total_size:,} bytes")
    print(f"  Filename stored    : {filename}")

    return final_payload


# NOTE: Legacy reference implementation — not used by main.py.
# main.py uses its own parse_payload() function.
# Kept for documentation and presentation purposes.
def recover_payload(payload_bytes, password, output_folder="."):
    """
    Takes hidden bytes and recovers the original secret file.

    This is the exact reverse of prepare_payload:
    1. Read and verify the header
    2. Extract salt, nonce, filename, encrypted data
    3. Derive the same key from password + salt
    4. Decrypt with AES-256-GCM
    5. Decompress
    6. Save recovered file

    Parameters:
        payload_bytes  : the bytes extracted from the stego image
        password       : string password (must match encoding password)
        output_folder  : where to save the recovered file

    Returns:
        path to recovered file, or None if failed
    """

    print("  Verifying payload...")

    # ── Step 1: Check MAGIC_BYTES ─────────────────────────
    if payload_bytes[:4] != MAGIC_BYTES:
        print("  ERROR: Invalid format or wrong password")
        return None

    # ── Step 2: Parse the header ──────────────────────────
    pos = 4

    salt = payload_bytes[pos : pos + 16]
    pos += 16

    nonce = payload_bytes[pos : pos + 12]
    pos += 12

    original_size = int.from_bytes(payload_bytes[pos : pos + 4], 'big')
    pos += 4

    filename_length = int.from_bytes(payload_bytes[pos : pos + 4], 'big')
    pos += 4

    filename_bytes = payload_bytes[pos : pos + filename_length]
    filename = filename_bytes.decode('utf-8')
    pos += filename_length

    encrypted = payload_bytes[pos:]

    print(f"  Filename found     : {filename}")
    print(f"  Expected size      : {original_size:,} bytes")

    # ── Step 3: Derive the same key ───────────────────────
    key = derive_key(password, salt)

    # ── Step 4: Decrypt ───────────────────────────────────
    aesgcm = AESGCM(key)

    try:
        compressed = aesgcm.decrypt(nonce, encrypted, None)
    except Exception:
        print("  ERROR: Decryption failed - wrong password or corrupted data")
        return None

    # ── Step 5: Decompress ────────────────────────────────
    try:
        raw_bytes = zlib.decompress(compressed)
    except Exception:
        print("  ERROR: Decompression failed - data corrupted")
        return None

    if len(raw_bytes) != original_size:
        print(f"  WARNING: Size mismatch. "
              f"Expected {original_size}, got {len(raw_bytes)}")

    # ── Step 6: Save the recovered file ───────────────────
    output_path = os.path.join(output_folder, "recovered_" + filename)

    with open(output_path, 'wb') as f:
        f.write(raw_bytes)

    print(f"  File recovered     : {output_path}")
    print(f"  Recovered size     : {len(raw_bytes):,} bytes")

    return output_path


# ============================================================
# TEST - Run this file directly to test payload preparation
# python payload.py
# ============================================================

if __name__ == "__main__":

    print("=" * 50)
    print("PAYLOAD MODULE TEST")
    print("=" * 50)

    # ── Test 1: Create a test secret file ─────────────────
    print("\nTest 1: Creating test secret file...")

    test_content = """This is my secret message.
    It can contain multiple lines.
    Numbers: 1234567890
    Special characters: !@#$%^&*()
    This entire file will be compressed, encrypted,
    and hidden inside an image."""

    with open("test_secret.txt", "w") as f:
        f.write(test_content)
    print("  Created: test_secret.txt")

    # ── Test 2: Prepare (encode) the payload ──────────────
    print("\nTest 2: Preparing payload (compress + encrypt)...")

    password = "my_test_password_123"

    payload = prepare_payload("test_secret.txt", password)

    print(f"  Payload ready: {len(payload):,} bytes total")

    # ── Test 3: Recover (decode) the payload ──────────────
    print("\nTest 3: Recovering payload (decrypt + decompress)...")

    recovered_path = recover_payload(payload, password, ".")

    # ── Test 4: Verify perfect recovery ───────────────────
    print("\nTest 4: Verifying perfect recovery...")

    if recovered_path and os.path.exists(recovered_path):
        with open("test_secret.txt", "r") as f:
            original_text = f.read()
        with open(recovered_path, "r") as f:
            recovered_text = f.read()

        if original_text == recovered_text:
            print("  SUCCESS! Recovered text is identical to original")
            print(f"  Original  : {len(original_text)} characters")
            print(f"  Recovered : {len(recovered_text)} characters")
        else:
            print("  FAILURE! Text does not match")

    # ── Test 5: Wrong password test ───────────────────────
    print("\nTest 5: Testing wrong password (should fail gracefully)...")

    result = recover_payload(payload, "wrong_password", ".")

    if result is None:
        print("  CORRECT - Wrong password was rejected")
    else:
        print("  ERROR - Wrong password was incorrectly accepted!")

    # ── Cleanup ───────────────────────────────────────────
    print("\nCleaning up test files...")
    for f in ["test_secret.txt", "recovered_test_secret.txt"]:
        if os.path.exists(f):
            os.remove(f)
            print(f"  Removed: {f}")

    print("\n" + "=" * 50)
    print("ALL TESTS COMPLETE")
    print("If you see SUCCESS above, payload.py is working.")
    print("=" * 50)
