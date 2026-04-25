# StegoVault

Hide and encrypt any file inside a PNG image using NC-LSBM steganography and AES-256-GCM encryption.

StegoVault is an academic steganography application built as a group project. It implements a novel **NC-LSBM (Neighborhood-Consistent LSB Matching)** algorithm that improves upon standard LSB Matching by using local pixel neighborhood prediction to minimize detectable residuals — making hidden data harder to detect by steganalysis tools like SRM.

---

## Table of Contents

- [Features](#features)
- [Algorithm — NC-LSBM](#algorithm--nc-lsbm)
- [Security](#security)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Running the App](#running-the-app)
- [API Endpoints](#api-endpoints)
- [Payload Format](#payload-format)
- [Code-Level Documentation](#code-level-documentation)
  - [payload.py](#payloadpy--detailed-explanations)
  - [stego.py](#stegopy--detailed-explanations)
  - [main.py](#mainpy--detailed-explanations)
- [Team](#team)

---

## Features

- **Hide any file type** — text, images, audio, video, PDF, ZIP, and more
- **NC-LSBM embedding** — novel neighborhood-consistent direction selection
- **AES-256-GCM encryption** — military-grade encryption with authentication
- **PBKDF2 key derivation** — 100,000 SHA-256 rounds, fresh salt per encode
- **Password-keyed pixel order** — SHA-256 permutation keeps visit order secret
- **Adaptive compression** — zlib for text, raw for already-compressed formats
- **Background-aware cost map** — scipy-based local variance + directional gradients
- **REST API** — FastAPI backend, usable from any frontend or tool
- **Web UI** — drag-and-drop HTML/JS frontend, no installation needed
- **Lossless PNG only** — JPEG/WEBP explicitly rejected to protect hidden bits

---

## Algorithm — NC-LSBM

### The Problem with Standard LSBM

Standard LSB Matching works by randomly choosing `+1` or `−1` when a pixel's LSB doesn't match the target bit. This random choice means 50% of modifications move the pixel value *away* from what its neighbors predict — creating a detectable statistical residual.

### Our Solution

NC-LSBM replaces the coin flip with a **neighborhood prediction**:

```
result = argmin over d ∈ {+1, −1} of | (v + d) − avg(neighbors) |
```

We compute the average of the pixel's horizontal neighbors (left and right), then choose whichever of `+1` or `−1` brings the pixel *closer* to that predicted value. This minimizes the local prediction residual at every single modified pixel.

### Why It's Better — The Proof

The correctness of NC-LSBM rests on a simple but provable theorem:

```
min(a, b) ≤ (a + b) / 2
```

For any two residual distances `a` and `b` (corresponding to `+1` and `−1`), the minimum is always less than or equal to the average. Standard LSBM picks the average in expectation (50/50 random). NC-LSBM always picks the minimum. Therefore:

> **NC-LSBM residual ≤ LSBM expected residual for every modified pixel. Provable, not empirical.**

### Cost Map

Pixel modification cost is computed using:

```
cost(r, c, ch) = 1 / (σ²_local + min(∇h, ∇v) + ε)
```

| Term | Meaning |
|------|---------|
| `σ²_local` | Local variance in a 5×5 window (scipy.ndimage) |
| `∇h` | Horizontal gradient: `\|pixel[r, c+1] − pixel[r, c−1]\|` |
| `∇v` | Vertical gradient: `\|pixel[r+1, c] − pixel[r-1, c]\|` |
| `min(∇h, ∇v)` | Safe only if complex in ALL directions (WOW insight) |
| `ε = 0.001` | Division-by-zero guard |

Low cost = textured region = safe to embed. High cost = smooth region = avoid.

### Pixel Visit Order

```
seed = SHA-256(password)[:8] → uint64
permutation = numpy.random.default_rng(seed).permutation(H × W × 3)
```

The permutation depends only on the password and image dimensions — never on pixel values. This guarantees encode and decode always visit the same pixels in the same order, even after NC-LSBM has modified pixel values by ±1.

---

## Security

| Property | Implementation |
|----------|---------------|
| Encryption | AES-256-GCM |
| Key derivation | PBKDF2-SHA256, 100,000 iterations |
| Salt | 16 random bytes, fresh per encode |
| Nonce | 12 random bytes, fresh per encode |
| Pixel order | SHA-256(password) → numpy permutation |
| Authentication | GCM auth tag — detects tampering |

Without the password:
- The pixel visit order is unknown
- Extracted bits are indistinguishable from noise
- Even knowing the magic bytes, AES-GCM authentication fails

---

## Project Structure

```
StegoVault/
│
├── files/
│   ├── index.html      # Web UI — drag-and-drop frontend (no framework)
│   ├── main.py          # FastAPI backend — routes, file handling, embedding
│   ├── payload.py       # Key derivation (derive_key), MAGIC_BYTES constant
│   └── stego.py         # Cost map, NC-LSBM reference implementation
│
├── requirements.txt     # Python dependencies
├── .gitignore
├── LICENSE
└── README.md
```

### Team Responsibilities

| Member | Area | Files |
|--------|------|-------|
| Member 1 | Algorithm & core engine | `stego.py` |
| Member 2 | Security & payload system | `payload.py` |
| Member 3 | System integration & frontend | `main.py`, `index.html` |

---

## Installation

**Requirements:** Python 3.10+

```bash
# 1. Clone the repository
git clone https://github.com/Prashant-26k/StegoVault.git
cd StegoVault

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running the App

```bash
# Start the backend server
uvicorn main:app --port 8000 --reload
```

Then open `index.html` in your browser (no server needed for the frontend).

The API docs are available at: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/capacity` | Embedding capacity for a cover PNG |
| `POST` | `/encode` | Hide a file inside a PNG |
| `POST` | `/decode` | Recover a hidden file from a stego PNG |

### POST /encode

| Field | Type | Description |
|-------|------|-------------|
| `cover_image` | file | PNG image (lossless only) |
| `secret_file` | file | Any file to hide |
| `password` | string | Encryption and permutation password |

Returns the stego PNG as a binary response with metadata in headers.

### POST /decode

| Field | Type | Description |
|-------|------|-------------|
| `stego_image` | file | PNG previously encoded by StegoVault |
| `password` | string | Same password used during encoding |

Returns JSON with the recovered file as base64.

---

## Payload Format

The binary payload embedded in the image follows this layout:

```
Bytes  0– 3  |  4 B  | Magic: "STEG"
Bytes  4–19  | 16 B  | PBKDF2-SHA256 salt
Bytes 20–31  | 12 B  | AES-GCM nonce
Bytes 32–35  |  4 B  | uint32 BE — original file size
Bytes 36–39  |  4 B  | uint32 BE — ciphertext length
Byte  40     |  1 B  | uint8     — filename length N
Bytes 41…    |  N B  | UTF-8     — filename
…            |  1 B  | uint8     — MIME type length M
…            |  M B  | UTF-8     — MIME type
…            |  1 B  | uint8     — compress flag (1 = zlib, 0 = raw)
Remaining    |       | AES-256-GCM ciphertext (+ 16 B auth tag)
```

---

## Code-Level Documentation

The sections below provide detailed explanations of the code logic, originally written as inline comments in the source files during development. They are collected here for reference and presentation.

---

### payload.py — Detailed Explanations

#### Imports

| Module | Purpose |
|--------|---------|
| `os` | Operating system tools — get file sizes, extract filenames |
| `zlib` | Compression (built into Python) — make files smaller before hiding |
| `struct` | Number ↔ bytes conversion — store file size as exactly 4 bytes (e.g. 1500 → `b'\x00\x00\x05\xDC'`) |
| `hashlib` | Cryptographic hashing — turn a password into an encryption key via PBKDF2 |
| `secrets` | Cryptographic randomness — generate the random salt and nonce for encryption |
| `AESGCM` | AES-256-GCM encryption (from `cryptography` library) — AES = Advanced Encryption Standard, GCM = Galois Counter Mode (also verifies data wasn't tampered with) |

#### Constants

- **`MAGIC_BYTES = b'STEG'`** — A 4-byte signature written at the start of every hidden payload. During decoding, we check for this to confirm: (1) the image actually contains hidden data, and (2) the password is correct (wrong password → wrong decryption → no `STEG` marker). The `b''` prefix marks it as raw bytes, not a regular string.

- **`HEADER_SIZE = 4 + 4 + 16 + 12 + 255 = 291`** — The fixed-size header used by the legacy reference implementation:
  - 4 bytes — magic bytes (`b'STEG'`)
  - 4 bytes — original file size (so the decoder knows how much data to read)
  - 16 bytes — AES encryption key salt (random, different every time)
  - 12 bytes — AES nonce (random number used once, required by GCM)
  - 255 bytes — original filename (padded to fixed size)
  - A fixed-size header ensures the decoder always knows exactly where the encrypted data starts.

#### `derive_key(password, salt)`

Converts a human-readable password into a fixed-size encryption key suitable for AES-256.

**Why this is needed:** AES-256 requires exactly 32 bytes as a key. A human password like `"hello123"` is only 8 bytes and not random enough. We need to "stretch" it into 32 random-looking bytes.

**How it works — PBKDF2:** We use PBKDF2 (Password Based Key Derivation Function 2). It runs SHA-256 100,000 times on the password combined with a random salt. This produces 32 bytes that look completely random but are always the same for the same password+salt combination.

**What is a salt?** A salt is a random value generated fresh each time we encrypt. It is stored in the payload header alongside the ciphertext. Even if two users choose the same password, their encryption keys will differ because their salts differ. The salt is not secret — the password is the secret. Without both the password *and* the salt, the key cannot be re-derived.

**Implementation steps:**
1. Convert password from string to bytes using `encode('utf-8')` — turns `"hello"` into `b'hello'`.
2. Call `hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, dklen=32)`:
   - `'sha256'` — the hashing algorithm
   - `password_bytes` — password as bytes
   - `salt` — the random salt
   - `100000` — iteration count (makes brute-force attacks slow)
   - `dklen=32` — output exactly 32 bytes for AES-256
3. The returned key is 32 bytes of derived randomness (e.g. `b'\x3f\xa2\x91\x0c...'`).

#### `prepare_payload(secret_file_path, password)` *(Legacy — not used by main.py)*

Takes any secret file and prepares it for embedding. `main.py` uses its own `build_payload()` instead; this function is kept for documentation and presentation.

| Step | Action | Detail |
|------|--------|--------|
| 1 | Read file | `'rb'` (read binary) reads any file type as raw bytes — text, image, PDF all become bytes |
| 2 | Compress | `zlib.compress(data, level=6)` — level 6 balances speed and compression ratio |
| 3 | Generate salt | `secrets.token_bytes(16)` — 16 truly random bytes, different every call |
| 4 | Derive key | Calls `derive_key(password, salt)` |
| 5 | Encrypt | Creates a 12-byte random nonce, then `AESGCM(key).encrypt(nonce, compressed, None)` — returns ciphertext with a 16-byte authentication tag appended |
| 6 | Build header | Concatenates: MAGIC (4B) + salt (16B) + nonce (12B) + original size (4B, big-endian) + filename length (4B) + filename (NB) + ciphertext |

Helper notes:
- `os.path.basename("C:/folder/secret.txt")` → `"secret.txt"` — extracts just the filename.
- `int.to_bytes(4, 'big')` converts an integer to 4 bytes in big-endian order (e.g. `12345` → `b'\x00\x003\x9'`).
- The `+` operator concatenates `bytes` objects.

#### `recover_payload(payload_bytes, password, output_folder)` *(Legacy — not used by main.py)*

The exact reverse of `prepare_payload` — `main.py` uses its own `parse_payload()` instead.

| Step | Action | Detail |
|------|--------|--------|
| 1 | Check magic | First 4 bytes must equal `b'STEG'` — wrong password or non-stego image fails here |
| 2 | Parse header | Read fields sequentially in the same order they were written: salt (16B), nonce (12B), original size (4B → int via `int.from_bytes()`), filename length (4B), filename (NB), remaining = ciphertext |
| 3 | Derive key | Same salt from header + same password → same key |
| 4 | Decrypt | `AESGCM(key).decrypt(nonce, ciphertext, None)` — fails automatically if password is wrong or data was tampered with (GCM authentication) |
| 5 | Decompress | `zlib.decompress(compressed)` reverses step 2 of encoding |
| 6 | Save file | `'wb'` (write binary) writes raw bytes to `recovered_<filename>` |

---

### stego.py — Detailed Explanations

#### `compute_cost_map(pixels)`

Computes the modification cost for every pixel-channel. Low cost = textured region = safe to modify. High cost = smooth region = dangerous.

The image is converted to `float64` first to prevent integer arithmetic rounding errors. The cost map is built channel by channel (R, G, B) with shape `(height, width, 3)`.

**Measurement 1 — Local Variance:**

Variance measures how spread out pixel values are in a neighbourhood. For each pixel's 5×5 window: (1) compute mean of all 25 values, (2) compute (value − mean)² for each, (3) average those squared differences.

`scipy.ndimage.uniform_filter(channel, size=5, mode='reflect')` efficiently computes step 1 for every pixel simultaneously. The variance formula `E[X²] − E[X]²` is used:
- `local_mean` = E[X] via uniform_filter on channel
- `local_mean_sq` = E[X²] via uniform_filter on channel²
- `local_variance = local_mean_sq − local_mean²`
- Clipped to ≥ 0 (floating-point precision can produce tiny negatives)

Interpretation: high variance = lots of different values nearby = textured = safe. Low variance = all similar values = smooth = dangerous.

**Measurement 2 — Directional Gradients:**

A gradient measures how much pixel value changes as you move in a direction.

- **Horizontal:** `|pixel[r, c+1] − pixel[r, c−1]|` — large means horizontal edge/texture, small means horizontally smooth.
- **Vertical:** `|pixel[r+1, c] − pixel[r−1, c]|` — large means vertical change, small means vertically smooth.

Implementation uses `np.roll` to shift the entire array: `np.roll(arr, -1, axis=1)` shifts left by 1 column, `np.roll(arr, +1, axis=1)` shifts right. "Shift right minus shift left" gives the difference across 2 pixels.

We take `min(horizontal, vertical)` — the **WOW insight**: a pixel is only truly safe if it is complex in ALL directions. If either direction is smooth, the pixel sits on or near an edge. Minimum enforces "must be complex in all directions".

**Cost formula:**

```
cost = 1 / (variance + min_gradient + ε)
```

`ε = 0.001` prevents division by zero for perfectly flat pixels. High variance + high gradient → large denominator → low cost (safe). Low variance + low gradient → small denominator → high cost (dangerous).

#### `get_pixel_order(cost_map, password)` *(Reference — not used by main.py)*

Determines the order in which pixels are visited for embedding with two goals: (1) visit cheapest (safest) pixels first, (2) make the order password-dependent.

Implementation:
- `np.ndindex(h, w, ch)` generates all (row, col, channel) index combinations. For a 100×100 RGB image: 30,000 tuples.
- `np.argsort(costs)` returns positions that would sort the array ascending. Example: costs = [0.5, 0.1, 0.8] → argsort = [1, 0, 2].
- Password → `hashlib.sha256` → first 4 bytes → integer seed → `np.random.default_rng(seed)`.
- Shuffle within blocks of 1000 similar-cost pixels: preserves general cost ordering while adding key-dependent variation.

#### `nc_lsbm_embed(pixel_value, target_bit, neighbors)` *(Reference — not used by main.py)*

The **novel contribution** — not present in HUGO, WOW, or S-UNIWARD.

| Standard LSBM | NC-LSBM (this work) |
|---------------|---------------------|
| LSB ≠ target? → random ±1 (coin flip) | LSB ≠ target? → compute neighbor average |
| 50% chance of suboptimal choice | Always pick ±1 closer to predicted value |
| Larger SRM residual | Minimized prediction residual |

**Implementation details:**
- LSB extraction: `pixel_value & 1` (bitwise AND with 1 extracts the last bit).
- If `current_lsb == target_bit`: no modification needed — zero distortion.
- Otherwise compute both options: `option_up = value + 1`, `option_down = value − 1`.
- **Boundary cases:** `value = 255` → can only go down (256 is invalid). `value = 0` → can only go up (−1 is invalid).

**Neighborhood prediction:**
- Predicted value = average of surrounding pixel values (what the pixel "should" be given its neighbours).
- If no neighbors exist (edge pixel with no valid adjacents): fall back to random choice.

**The key decision:**
- Prediction residual = `|actual − predicted|`
- Pick whichever option (up or down) produces the smaller residual.
- Example: pixel = 100, predicted = 98 → `|101 − 98| = 3`, `|99 − 98| = 1` → pick 99 (residual = 1). Standard LSBM would randomly pick either; NC-LSBM always picks the optimal direction.

#### `get_neighbors(pixels, row, col, channel)` *(Reference — not used by main.py)*

Returns the values of the 4 directly adjacent pixels (same channel): above (row−1, col), below (row+1, col), left (row, col−1), right (row, col+1). Each direction is bounds-checked before access. Edge pixels naturally have fewer than 4 neighbors.

---

### main.py — Detailed Explanations

#### Adaptive Compression Strategy

`main.py` detects the file type via browser MIME hint → filename extension → magic byte signatures, then applies the appropriate compression strategy:

| Category | Strategy | Examples |
|----------|----------|----------|
| `text` | zlib level-9 (huge savings, often 90–99%) | TXT, JSON, XML, HTML, CSV, SQL |
| `image` | zlib if result is smaller, else raw | PNG, BMP, TIFF try compress; JPEG, GIF, WEBP stored raw |
| `audio` | raw (already compressed) | MP3, AAC, WAV, OGG, FLAC |
| `video` | raw (already compressed) | MP4, WEBM, MKV, AVI |
| `archive` | raw (already compressed) | ZIP, RAR, 7z, gzip, bzip2 |
| `binary` | raw (safest default) | Unknown `application/octet-stream` |

#### Pixel Ordering & Embedding

`SHA-256(password)[:8]` → numpy seed → full H×W×3 permutation. Depends only on password + dimensions, never on pixel values. Encode and decode always visit the same pixels in the same order.

Embedding is fully vectorized using `np.unpackbits` / `np.packbits` — no Python loops. NC-LSBM direction is chosen from horizontal neighbor prediction.

#### Bug Fix: Pixel Ordering Mismatch

The previous version used `_safe_indices()` to filter out near-black (`rgb_sum < 24`) and near-white (`rgb_sum > 741`) pixels before building the embedding permutation. This caused a critical encode/decode mismatch:

- During **ENCODE**: `_safe_indices` ran on the original cover image.
- During **DECODE**: `_safe_indices` ran on the stego image, where NC-LSBM had already changed some pixel values by ±1.

A pixel at exactly `rgb_sum == 23` in the cover could become `rgb_sum == 24` after embedding (or vice versa), flipping its membership in the "safe" set. This shifted every subsequent index in the permutation, so extracted bits no longer started with `MAGIC_BYTES`.

Text files worked *by coincidence*: their payloads are small and likely landed entirely before any threshold-crossing pixel in the permutation order.

**Fix:** Use ALL pixels for embedding. A ±1 LSB change is perceptually invisible on any pixel value. Near-black/white pixels are rare in natural photographs, and the AES-GCM ciphertext already looks like random noise regardless of which pixels carry it — there is no steganalytic advantage to skipping them.

---

## Team

Built as an academic group project.
Algorithm concept, implementation, and documentation by the StegoVault team.
