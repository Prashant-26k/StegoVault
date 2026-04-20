# ============================================================
# payload.py - Secret File Preparation and Recovery
# ============================================================
# This file handles everything EXCEPT the actual image hiding.
# It takes any secret file, prepares it for hiding, and can
# recover the original file from the prepared data.
#
# Think of this as the "packaging department" of your system.
# ============================================================


# --- IMPORTS ---
# These are tools Python gives us. We just need to ask for them.

import os       # os = operating system tools
                # We use it to: get file sizes, get filenames

import zlib     # zlib = compression tool (built into Python)
                # We use it to: make files smaller before hiding

import struct   # struct = converts numbers to/from bytes
                # We use it to: store the file size as exactly 4 bytes
                # Example: the number 1500 stored as b'\x00\x00\x05\xDC'

import hashlib  # hashlib = creates fixed-size "fingerprints" of data
                # We use it to: turn a password into an encryption key

import secrets  # secrets = generates truly random numbers
                # We use it to: create the random "salt" for encryption

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# AESGCM = AES-256-GCM encryption
# AES = Advanced Encryption Standard (military grade)
# GCM = Galois Counter Mode (also checks data wasn't tampered with)
# We use it to: encrypt and decrypt our compressed file data


# --- CONSTANTS ---
# These are fixed values that never change during the program.
# Writing them here at the top means if we ever need to change
# them, we only change them in one place.

MAGIC_BYTES = b'STEG'
# b'STEG' = our secret signature (4 bytes)
# Every file hidden by our algorithm starts with this
# During decoding, we check for this to confirm:
#   1. This image actually has hidden data
#   2. The password is correct (wrong password = wrong decryption = no STEG)
# b'' means this is bytes, not a regular string

HEADER_SIZE = 4 + 4 + 16 + 12 + 255
# Our header contains several fixed-size pieces:
#   4 bytes  = magic bytes (b'STEG')
#   4 bytes  = original file size (so we know how much to read)
#  16 bytes  = AES encryption key salt (random, different every time)
#  12 bytes  = AES nonce (random number used once, required by GCM)
# 255 bytes  = original filename (padded to fixed size)
# Total = 291 bytes
# Fixed size header means decoder always knows exactly where data starts


# ============================================================
# FUNCTION 1 - derive_key()
# Turns a password string into a 32-byte encryption key
# ============================================================

def derive_key(password, salt):
    """
    Converts a human password into a fixed-size encryption key.

    WHY WE NEED THIS:
    AES-256 encryption requires exactly 32 bytes as a key.
    A human password like "hello123" is only 8 bytes and not
    random enough. We need to "stretch" it into 32 random-looking bytes.

    HOW IT WORKS:
    We use PBKDF2 - Password Based Key Derivation Function 2.
    It runs SHA-256 (a hashing algorithm) 100,000 times on
    your password combined with a random salt. This produces
    32 bytes that look completely random but are always the
    same for the same password+salt combination.

    WHAT IS A SALT?
    A salt is a random number we generate fresh each time we
    encrypt. We store it in the header alongside the encrypted
    data. This means even if two people use the same password,
    their encryption keys will be different (different salts).
    Without the salt, you cannot derive the key even if you
    know the password... but we store the salt openly in the
    header because it is not secret - the password is the secret.

    Parameters:
        password : string  - the user's password e.g. "mysecret"
        salt     : bytes   - 16 random bytes generated fresh each time

    Returns:
        key      : bytes   - exactly 32 bytes, ready for AES-256
    """

    # Step 1: Convert password from string to bytes
    # encode() turns "hello" into b'hello' (raw bytes)
    password_bytes = password.encode('utf-8')
    # 'utf-8' is the encoding standard - just always use this

    # Step 2: Use PBKDF2 to derive the key
    # hashlib.pbkdf2_hmac() takes:
    #   'sha256'         = the hashing algorithm to use
    #   password_bytes   = your password as bytes
    #   salt             = the random salt
    #   100000           = run the hash 100,000 times (makes it slow
    #                      for attackers trying to guess passwords)
    #   dklen=32         = output exactly 32 bytes
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        100000,
        dklen=32
    )

    return key
    # key is now 32 bytes of derived randomness
    # Example: b'\x3f\xa2\x91\x0c...' (32 bytes, looks random)


# ============================================================
# TEST - Run this section to verify imports work
# ============================================================
# To test: python payload.py
# You should see: "All imports successful!"

# if __name__ == "__main__":
    print("Testing payload.py imports...")
    print(f"  os module: OK")
    print(f"  zlib module: OK")
    print(f"  struct module: OK")
    print(f"  hashlib module: OK")
    print(f"  secrets module: OK")
    print(f"  AESGCM module: OK")
    print(f"  MAGIC_BYTES: {MAGIC_BYTES}")
    print(f"  HEADER_SIZE: {HEADER_SIZE} bytes")
    print()
    print("All imports successful!")
    print("Ready to add the next piece.")

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
    # 'rb' means read binary - reads any file type as raw bytes
    # A text file, image, PDF - all become raw bytes
    with open(secret_file_path, 'rb') as f:
        raw_bytes = f.read()
    
    original_size = len(raw_bytes)
    print(f"  Original file size : {original_size:,} bytes")
    
    # ── Step 2: Compress ──────────────────────────────────
    # zlib.compress() makes the data smaller
    # level=6 is balanced between speed and compression ratio
    compressed = zlib.compress(raw_bytes, level=6)
    compressed_size = len(compressed)
    
    ratio = (1 - compressed_size / original_size) * 100
    print(f"  Compressed size    : {compressed_size:,} bytes "
          f"({ratio:.1f}% smaller)")
    
    # ── Step 3: Generate random salt ──────────────────────
    # secrets.token_bytes(16) generates 16 truly random bytes
    # Different every single time this function is called
    salt = secrets.token_bytes(16)
    
    # ── Step 4: Derive encryption key ─────────────────────
    key = derive_key(password, salt)
    
    # ── Step 5: Encrypt ───────────────────────────────────
    # AESGCM needs exactly 12 random bytes as a nonce
    # A nonce is like a salt for encryption - random each time
    nonce = secrets.token_bytes(12)
    
    # Create the AES-GCM cipher with our derived key
    aesgcm = AESGCM(key)
    
    # encrypt(nonce, data, additional_data)
    # additional_data=None means no extra authentication data
    # Returns encrypted bytes with authentication tag appended
    encrypted = aesgcm.encrypt(nonce, compressed, None)
    
    print(f"  Encrypted size     : {len(encrypted):,} bytes")
    
    # ── Step 6: Build the header ──────────────────────────
    # We need to store metadata so the decoder knows what to recover
    # Header structure:
    #   4 bytes  : MAGIC (b'STEG') - format identifier
    #  16 bytes  : salt - needed to re-derive the key
    #  12 bytes  : nonce - needed for decryption
    #   4 bytes  : original file size as integer
    #   4 bytes  : filename length as integer
    #   N bytes  : filename as bytes
    
    # Get just the filename, not the full path
    # os.path.basename("C:/folder/secret.txt") → "secret.txt"
    filename = os.path.basename(secret_file_path)
    filename_bytes = filename.encode('utf-8')
    filename_length = len(filename_bytes)
    
    # to_bytes() converts an integer to bytes
    # (4, 'big') means: use 4 bytes, big-endian byte order
    # Example: 12345 → b'\x00\x003\x9'  (4 bytes)
    original_size_bytes = original_size.to_bytes(4, 'big')
    filename_length_bytes = filename_length.to_bytes(4, 'big')
    
    # Build complete payload by joining all parts
    # The + operator joins bytes objects together
    final_payload = (
        MAGIC_BYTES                 +  # 4  bytes: format marker
        salt                   +  # 16 bytes: for key derivation
        nonce                  +  # 12 bytes: for decryption
        original_size_bytes    +  # 4  bytes: original file size
        filename_length_bytes  +  # 4  bytes: filename length
        filename_bytes         +  # N  bytes: actual filename
        encrypted                 # rest:     encrypted data
    )
    
    total_size = len(final_payload)
    print(f"  Final payload size : {total_size:,} bytes")
    print(f"  Filename stored    : {filename}")
    
    return final_payload


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
    
    # ── Step 1: Check MAGIC_BYTES number ────────────────────────
    # Read first 4 bytes and check they equal b'STEG'
    if payload_bytes[:4] != MAGIC_BYTES:
        print("  ERROR: Invalid format or wrong password")
        return None
    
    # ── Step 2: Parse the header ──────────────────────────
    # We read the header fields in exactly the same order
    # we wrote them in prepare_payload
    
    # Current position in the byte stream
    pos = 4  # We already read 4 bytes (MAGIC_BYTES)
    
    # Read salt (16 bytes)
    salt = payload_bytes[pos : pos + 16]
    pos += 16
    
    # Read nonce (12 bytes)
    nonce = payload_bytes[pos : pos + 12]
    pos += 12
    
    # Read original file size (4 bytes → integer)
    # int.from_bytes() is the reverse of to_bytes()
    original_size = int.from_bytes(payload_bytes[pos : pos + 4], 'big')
    pos += 4
    
    # Read filename length (4 bytes → integer)
    filename_length = int.from_bytes(payload_bytes[pos : pos + 4], 'big')
    pos += 4
    
    # Read filename (filename_length bytes → string)
    filename_bytes = payload_bytes[pos : pos + filename_length]
    filename = filename_bytes.decode('utf-8')
    pos += filename_length
    
    # Everything remaining is the encrypted data
    encrypted = payload_bytes[pos:]
    
    print(f"  Filename found     : {filename}")
    print(f"  Expected size      : {original_size:,} bytes")
    
    # ── Step 3: Derive the same key ───────────────────────
    # MUST use the same salt that was stored in the header
    # Same password + same salt → same key
    key = derive_key(password, salt)
    
    # ── Step 4: Decrypt ───────────────────────────────────
    aesgcm = AESGCM(key)
    
    try:
        # decrypt() will FAIL if:
        # - Wrong password (produces wrong key → authentication fails)
        # - Data was tampered with
        # This is AES-GCM's authentication feature
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
    
    # Verify size matches what we stored
    if len(raw_bytes) != original_size:
        print(f"  WARNING: Size mismatch. "
              f"Expected {original_size}, got {len(raw_bytes)}")
    
    # ── Step 6: Save the recovered file ───────────────────
    output_path = os.path.join(output_folder, "recovered_" + filename)
    
    # 'wb' means write binary - writes raw bytes to file
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
    
    # This block only runs when you run payload.py directly
    # It does NOT run when stego.py imports payload.py
    # This is what "if __name__ == '__main__'" means
    
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
    
    # Write test file
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
