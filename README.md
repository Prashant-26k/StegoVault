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
├── index.html          # Web UI — drag-and-drop frontend (no framework)
├── main.py             # FastAPI backend — routes, file handling, embedding
├── payload.py          # Key derivation (derive_key), MAGIC_BYTES constant
├── stego.py            # Cost map, NC-LSBM reference implementation
│
├── requirements.txt    # Python dependencies
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
git clone https://github.com/your-username/StegoVault.git
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

## Team

Built as an academic group project.  
Algorithm concept, implementation, and documentation by the StegoVault team.
