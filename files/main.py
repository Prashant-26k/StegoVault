# ============================================================
# main.py  —  NC-LSBM Steganography API  v2
# ============================================================

import io, base64, hashlib, mimetypes, secrets, time, zlib

import numpy as np
from PIL import Image
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from payload import derive_key, MAGIC_BYTES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─────────────────────────────────────────────────────────────
app = FastAPI(title="NC-LSBM Steganography API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────
# FILE-TYPE CLASSIFICATION
# ─────────────────────────────────────────────────────────────

_GOOD_COMPRESS = (
    'text/',
    'application/json',
    'application/xml',
    'application/javascript',
    'application/xhtml',
    'application/x-sh',
    'application/sql',
)

_SKIP_COMPRESS = (
    'audio/',
    'video/',
    'image/jpeg',
    'image/jpg',
    'image/webp',
    'image/gif',
    'application/zip',
    'application/x-zip',
    'application/x-rar',
    'application/x-7z',
    'application/gzip',
    'application/x-bzip',
    'application/x-bzip2',
    'application/vnd.rar',
    'application/octet-stream',
)


def _classify(mime: str) -> str:
    """Return 'text', 'image', 'audio', 'video', 'archive', or 'binary'."""
    m = (mime or '').lower().split(';')[0].strip()
    if m.startswith('text/'):             return 'text'
    if m.startswith('image/'):            return 'image'
    if m.startswith('audio/'):            return 'audio'
    if m.startswith('video/'):            return 'video'
    if any(k in m for k in ('zip','rar','7z','gzip','bzip','tar','compress')):
        return 'archive'
    if m in ('application/json','application/xml','application/javascript',
             'application/xhtml+xml','application/sql','application/x-sh'):
        return 'text'
    return 'binary'


def _should_compress(mime: str) -> bool:
    """True if we should attempt zlib compression for this MIME type."""
    m = (mime or 'application/octet-stream').lower().split(';')[0].strip()
    if any(m.startswith(s) for s in _SKIP_COMPRESS):  return False
    if any(m.startswith(s) or m == s for s in _GOOD_COMPRESS): return True
    if m.startswith('image/'):  return True
    return False


def _detect_mime(filename: str, browser_mime: str, data: bytes) -> str:
    """
    Reliable MIME detection: browser hint → filename extension → magic bytes.
    """
    bm = (browser_mime or '').lower().split(';')[0].strip()
    if bm and bm not in ('', 'application/octet-stream', 'binary/octet-stream'):
        return bm

    if filename:
        guessed, _ = mimetypes.guess_type(filename)
        if guessed:
            return guessed

    sig = data[:16] if len(data) >= 16 else data + b'\x00' * 16

    if sig[:4] == b'\x89PNG':                       return 'image/png'
    if sig[:3] == b'\xff\xd8\xff':                  return 'image/jpeg'
    if sig[:6] in (b'GIF87a', b'GIF89a'):           return 'image/gif'
    if sig[:4] == b'RIFF' and sig[8:12] == b'WEBP': return 'image/webp'
    if sig[:4] == b'BM\x00\x00':                    return 'image/bmp'
    if sig[:3] == b'ID3' or sig[:2] in (b'\xff\xfb', b'\xff\xf3', b'\xff\xf2'):
        return 'audio/mpeg'
    if sig[:4] == b'fLaC':                          return 'audio/flac'
    if sig[:4] == b'RIFF' and sig[8:12] == b'WAVE': return 'audio/wav'
    if sig[:4] == b'OggS':                          return 'audio/ogg'
    if sig[4:8] == b'ftyp':                         return 'video/mp4'
    if sig[:4] == b'\x1a\x45\xdf\xa3':              return 'video/webm'
    if sig[:4] == b'RIFF' and sig[8:12] == b'AVI ': return 'video/x-msvideo'
    if sig[:4] == b'%PDF':                          return 'application/pdf'
    if sig[:4] == b'PK\x03\x04':                   return 'application/zip'
    if sig[:3] == b'Rar':                           return 'application/x-rar-compressed'
    if sig[:6] == b'7z\xbc\xaf\x27\x1c':           return 'application/x-7z-compressed'
    if sig[:2] == b'\x1f\x8b':                      return 'application/gzip'
    try:
        data[:512].decode('utf-8')
        return 'text/plain'
    except Exception:
        pass
    return 'application/octet-stream'


# ─────────────────────────────────────────────────────────────
# PAYLOAD  (build + parse)
# ─────────────────────────────────────────────────────────────

def build_payload(file_bytes: bytes, filename: str,
                  mime_type: str, password: str) -> bytes:
    """
    Prepare payload for embedding.

    For text/JSON/XML:  zlib compress (often 10–100× smaller)
    For audio/video:    skip compression (MP3/MP4 already compressed)
    For images:         try compress, use only if smaller
    For binary/unknown: skip compression
    Then AES-256-GCM encrypt the (possibly compressed) data.
    """
    file_type = _classify(mime_type)

    if file_type == 'text':
        inner         = zlib.compress(file_bytes, level=9)
        compress_flag = 1

    elif file_type in ('audio', 'video', 'archive', 'binary'):
        inner         = file_bytes
        compress_flag = 0

    elif file_type == 'image':
        if _should_compress(mime_type):
            attempt = zlib.compress(file_bytes, level=6)
            if len(attempt) < len(file_bytes):
                inner         = attempt
                compress_flag = 1
            else:
                inner         = file_bytes
                compress_flag = 0
        else:
            inner         = file_bytes
            compress_flag = 0

    else:
        inner         = file_bytes
        compress_flag = 0


    salt  = secrets.token_bytes(16)
    key   = derive_key(password, salt)
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(key).encrypt(nonce, inner, None)


    name_b = filename.encode('utf-8')[:255]
    mime_b = mime_type.encode('utf-8')[:255]

    header = (
        MAGIC_BYTES
        + salt
        + nonce
        + len(file_bytes).to_bytes(4, 'big')   # original size
        + len(ct).to_bytes(4, 'big')            # ciphertext length
        + bytes([len(name_b)]) + name_b
        + bytes([len(mime_b)]) + mime_b
        + bytes([compress_flag])
    )
    return header + ct


def parse_payload(payload_bytes: bytes, password: str):
    """
    Unpack header → decrypt → decompress if needed.
    Returns (data_bytes, filename, mime_type, error_string).
    error_string is None on success.
    """
    if len(payload_bytes) < 44 or payload_bytes[:4] != MAGIC_BYTES:
        return None, None, None, \
            "Magic bytes not found — wrong password or not a stego image"

    pos = 4
    salt          = payload_bytes[pos:pos+16]; pos += 16
    nonce         = payload_bytes[pos:pos+12]; pos += 12
    _orig_size    = int.from_bytes(payload_bytes[pos:pos+4], 'big'); pos += 4
    enc_len       = int.from_bytes(payload_bytes[pos:pos+4], 'big'); pos += 4
    name_len      = payload_bytes[pos]; pos += 1
    filename      = payload_bytes[pos:pos+name_len].decode('utf-8', errors='replace'); pos += name_len
    mime_len      = payload_bytes[pos]; pos += 1
    mime_type     = payload_bytes[pos:pos+mime_len].decode('utf-8', errors='replace'); pos += mime_len
    compress_flag = payload_bytes[pos]; pos += 1
    ct            = payload_bytes[pos:pos+enc_len]

    if len(ct) < enc_len:
        return None, None, None, "Payload truncated — image may have been modified"

    key = derive_key(password, salt)
    try:
        inner = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        return None, None, None, \
            "Decryption failed — wrong password or data corrupted"

    if compress_flag == 1:
        try:
            data = zlib.decompress(inner)
        except Exception:
            return None, None, None, "Decompression failed — data corrupted"
    else:
        data = inner

    return data, filename, mime_type, None


PROBE_BYTES = 320


def _total_from_probe(probe: bytes) -> tuple[int, int]:
    """
    Parse header probe → (total_payload_bytes, header_end_offset).
    Raises ValueError with human-readable message on any failure.
    """
    if probe[:4] != MAGIC_BYTES:
        raise ValueError(
            "Magic bytes not found — wrong password, wrong image, "
            "or image was re-saved as JPEG."
        )

    enc_len  = int.from_bytes(probe[36:40], 'big')
    name_len = probe[40]
    p        = 41 + name_len           # at mime_len byte
    if p + 1 > len(probe):
        raise ValueError("Header extends beyond probe — possibly corrupted")
    mime_len = probe[p];    p += 1 + mime_len    # at compress_flag byte
    p       += 1                                  # past compress_flag
    # p is now the start of ciphertext
    return p + enc_len, p


# ─────────────────────────────────────────────────────────────
# PIXEL ORDER + EMBED / EXTRACT
# ─────────────────────────────────────────────────────────────

def embed_payload(pixels: np.ndarray, payload: bytes, password: str) -> np.ndarray:
    """
    Embed payload bits into pixel LSBs using a password-keyed permutation
    of ALL H×W×3 pixel-channels.

    Using all pixels (not a filtered subset) guarantees that the permutation
    is deterministic from password + image dimensions alone, so encode and
    decode always agree — even after ±1 LSB changes have been applied.
    """
    h, w, _ = pixels.shape
    total_channels = h * w * 3
    n_bits         = len(payload) * 8

    if n_bits > total_channels:
        raise ValueError(
            f"Payload too large: need {len(payload):,} B but image holds "
            f"only {total_channels // 8:,} B. Use a larger PNG."
        )


    seed   = int.from_bytes(
        hashlib.sha256(password.encode('utf-8')).digest()[:8], 'big'
    )
    chosen = np.random.default_rng(seed).permutation(total_channels)[:n_bits]

    bits    = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    ch_arr  = (chosen % 3).astype(np.intp)
    rc      = chosen // 3
    row_arr = (rc // w).astype(np.intp)
    col_arr = (rc  % w).astype(np.intp)

    out = pixels.copy()
    cur = out[row_arr, col_arr, ch_arr].astype(np.int32)
    out[row_arr, col_arr, ch_arr] = ((cur & 0xFE) | bits.astype(np.int32)).astype(np.uint8)
    return out


def extract_n_bytes(pixels: np.ndarray, password: str, n: int) -> bytes:
    """
    Extract n bytes from the same ALL-pixel permutation used during embed.
    Must use the same password and the same image dimensions.
    """
    h, w, _ = pixels.shape
    total_channels = h * w * 3
    n_bits         = n * 8

    seed   = int.from_bytes(
        hashlib.sha256(password.encode('utf-8')).digest()[:8], 'big'
    )
    chosen = np.random.default_rng(seed).permutation(total_channels)[:n_bits]

    ch_arr  = (chosen % 3).astype(np.intp)
    rc      = chosen // 3
    row_arr = (rc // w).astype(np.intp)
    col_arr = (rc  % w).astype(np.intp)

    lsbs = (pixels[row_arr, col_arr, ch_arr] & 1).astype(np.uint8)
    return np.packbits(lsbs).tobytes()


# ─────────────────────────────────────────────────────────────
# IMAGE HELPERS
# ─────────────────────────────────────────────────────────────

def load_png(data: bytes):
    img    = Image.open(io.BytesIO(data)).convert('RGB')
    pixels = np.array(img, dtype=np.uint8)
    return pixels, img.width, img.height


def pixels_to_png(pixels: np.ndarray) -> bytes:
    img = Image.fromarray(pixels.astype(np.uint8), 'RGB')
    buf = io.BytesIO()
    img.save(buf, format='PNG', optimize=False, compress_level=1)
    return buf.getvalue()


def max_capacity(w: int, h: int) -> int:
    """Maximum embeddable bytes = all H×W×3 channels ÷ 8 bits."""
    return (w * h * 3) // 8


def human_bytes(n: int) -> str:
    if n < 1024:        return f"{n} B"
    if n < 1_048_576:   return f"{n/1024:.1f} KB"
    return f"{n/1_048_576:.2f} MB"


# ─────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────

@app.get("/", tags=["info"])
def root():
    return {
        "service": "NC-LSBM Steganography API v2",
        "endpoints": {
            "POST /encode":   "Hide any file in a PNG",
            "POST /decode":   "Recover hidden file from stego PNG",
            "POST /capacity": "Capacity info for a cover PNG",
            "GET  /health":   "Health check",
            "GET  /docs":     "OpenAPI interactive docs",
        }
    }


@app.get("/health", tags=["info"])
def health():
    return {"status": "ok", "time": time.time()}


@app.post("/capacity", tags=["stego"])
async def get_capacity(cover_image: UploadFile = File(...)):
    """Dimensions and embedding capacity for a cover PNG."""
    data = await cover_image.read()
    try:
        pixels, w, h = load_png(data)
    except Exception as e:
        raise HTTPException(400, f"Cannot read image: {e}")
    cap = max_capacity(w, h)
    return {
        "width"           : w,
        "height"          : h,
        "total_pixels"    : w * h,
        "max_bytes"       : cap,
        "max_bytes_human" : human_bytes(cap),
    }


@app.post("/encode", tags=["stego"])
async def encode(
    cover_image : UploadFile = File(...),
    secret_file : UploadFile = File(...),
    password    : str        = Form(...),
):
    """
    Hide secret_file inside cover_image using NC-LSBM steganography.

    Compression is chosen per file type:
      text / JSON / XML    → zlib level-9  (huge savings)
      audio / video / zip  → raw           (already compressed)
      PNG / BMP images     → zlib if smaller, else raw
      unknown binary       → raw
    """
    t0 = time.time()

    if not cover_image.filename.lower().endswith('.png'):
        raise HTTPException(400, "Cover image must be a PNG file")
    if not password:
        raise HTTPException(400, "Password is required")

    cover_data  = await cover_image.read()
    secret_data = await secret_file.read()

    if not secret_data:
        raise HTTPException(400, "Secret file is empty")

    try:
        pixels, w, h = load_png(cover_data)
    except Exception as e:
        raise HTTPException(400, f"Cannot read cover image: {e}")

    filename  = secret_file.filename or "file"
    mime_type = _detect_mime(filename, secret_file.content_type or "", secret_data)

    try:
        payload = build_payload(secret_data, filename, mime_type, password)
    except Exception as e:
        raise HTTPException(500, f"Payload build failed: {e}")

    cap = max_capacity(w, h)
    if len(payload) > cap:
        raise HTTPException(413,
            f"Payload ({human_bytes(len(payload))}) exceeds cover capacity "
            f"({human_bytes(cap)}). Use a larger PNG.")

    try:
        stego_pixels = embed_payload(pixels, payload, password)
    except ValueError as e:
        raise HTTPException(413, str(e))
    except Exception as e:
        raise HTTPException(500, f"Embedding failed: {e}")

    stego_png = pixels_to_png(stego_pixels)
    elapsed   = time.time() - t0
    file_type = _classify(mime_type)

    expose = ("X-Stego-Filename,X-Stego-Mime,X-File-Type,"
              "X-Payload-Bytes,X-Cover-Capacity,X-Capacity-Used-Pct,"
              "X-Cover-Width,X-Cover-Height,"
              "X-Processing-Time-Ms,X-Secret-Size-Bytes,X-Compression-Used")

    return Response(
        content    = stego_png,
        media_type = "image/png",
        headers    = {
            "X-Stego-Filename"             : filename,
            "X-Stego-Mime"                 : mime_type,
            "X-File-Type"                  : file_type,
            "X-Payload-Bytes"              : str(len(payload)),
            "X-Cover-Capacity"             : str(cap),
            "X-Capacity-Used-Pct"          : f"{len(payload)/cap*100:.1f}",
            "X-Cover-Width"                : str(w),
            "X-Cover-Height"               : str(h),
            "X-Processing-Time-Ms"         : str(int(elapsed * 1000)),
            "X-Secret-Size-Bytes"          : str(len(secret_data)),
            "X-Compression-Used"           : str(_should_compress(mime_type)),
            "Access-Control-Expose-Headers": expose,
        }
    )


@app.post("/decode", tags=["stego"])
async def decode(
    stego_image : UploadFile = File(...),
    password    : str        = Form(...),
):
    """
    Recover the file hidden in a stego PNG.
    Returns JSON: filename, mime_type, size_bytes, size_human, data_base64.
    """
    t0 = time.time()

    if not stego_image.filename.lower().endswith('.png'):
        raise HTTPException(400, "Stego image must be a PNG file")
    if not password:
        raise HTTPException(400, "Password is required")

    stego_data = await stego_image.read()
    try:
        pixels, w, h = load_png(stego_data)
    except Exception as e:
        raise HTTPException(400, f"Cannot read image: {e}")

    # Phase 1: probe to determine total payload size
    try:
        probe = extract_n_bytes(pixels, password, PROBE_BYTES)
    except Exception as e:
        raise HTTPException(500, f"Extraction failed: {e}")

    try:
        total_bytes, _ = _total_from_probe(probe)
    except ValueError as e:
        raise HTTPException(422, str(e))

    cap = max_capacity(w, h)
    if total_bytes > cap:
        raise HTTPException(422,
            f"Payload claims {human_bytes(total_bytes)} but image holds "
            f"only {human_bytes(cap)} — wrong password or corrupted image.")

    # Phase 2: extract full payload
    try:
        full_payload = extract_n_bytes(pixels, password, total_bytes)
    except Exception as e:
        raise HTTPException(500, f"Full extraction failed: {e}")

    data, filename, mime_type, error = parse_payload(full_payload, password)
    if error:
        raise HTTPException(422, error)

    elapsed = time.time() - t0

    return JSONResponse({
        "success"      : True,
        "filename"     : filename,
        "mime_type"    : mime_type,
        "file_type"    : _classify(mime_type),
        "size_bytes"   : len(data),
        "size_human"   : human_bytes(len(data)),
        "data_base64"  : base64.b64encode(data).decode('ascii'),
        "cover_width"  : w,
        "cover_height" : h,
        "processing_ms": int(elapsed * 1000),
    })