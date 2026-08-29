import streamlit as st
from PIL import Image
import numpy as np
from Crypto.Cipher import AES, ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import io
import hashlib
import math
import random
from pathlib import Path
from sklearn.tree import DecisionTreeClassifier
from scipy.fftpack import dct, idct

# =====================================================================
# AES
# =====================================================================
def encrypt_aes(message, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()

def decrypt_aes(encrypted_text, password):
    data = base64.b64decode(encrypted_text)
    salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# =====================================================================
# ChaCha20
# =====================================================================
def encrypt_chacha(message, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(message.encode())
    return base64.b64encode(salt + cipher.nonce + ciphertext).decode()

def decrypt_chacha(encrypted_text, password):
    data = base64.b64decode(encrypted_text)
    salt, nonce, ciphertext = data[:16], data[16:24], data[24:]
    key = PBKDF2(password, salt, dkLen=32)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

# =====================================================================
# Integrity (SHA-256)
# =====================================================================
def compute_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

# =====================================================================
# Feature extraction — what the agent "looks at" before deciding
# =====================================================================
def message_entropy(text):
    """Shannon entropy of the message — measures how random/dense the text is.
    Plain English sentences score low (~3.5-4.2). Random-looking text scores higher (~4.5+)."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_features(message, capacity_bits):
    length = len(message)
    entropy = message_entropy(message)
    capacity_ratio = (length * 8) / capacity_bits if capacity_bits else 0
    return {
        "length": length,
        "entropy": entropy,
        "capacity_ratio": capacity_ratio,
    }

# =====================================================================
# THE AGENT — a small trained ML model, not a hardcoded if/else
# =====================================================================
@st.cache_resource
def train_agent():
    """
    Trains a lightweight Decision Tree on synthetic labelled examples.
    Labelling rule used to GENERATE training data (the 'expert knowledge'
    we are teaching the model, mirroring how real security policy is set):
      - short, low-entropy messages  -> AES-GCM (strong authenticated encryption,
        cost of AES is negligible at small sizes)
      - long or high-entropy messages -> ChaCha20 (faster on large/dense payloads,
        avoids AES overhead at scale)
      - messages that would use a large share of the image's capacity -> ChaCha20
        (favours speed since more data has to be processed and embedded)
    The MODEL itself learns the boundary from these examples rather than
    us hardcoding a single threshold — so it generalizes across combinations
    of length, entropy, and capacity instead of checking one number.
    """
    random.seed(42)
    X, y = [], []
    for _ in range(400):
        length = random.randint(1, 500)
        entropy = random.uniform(1.5, 5.5)
        capacity_ratio = random.uniform(0.0001, 0.05)

        score = 0
        if length > 50:
            score += 1
        if entropy > 4.2:
            score += 1
        if capacity_ratio > 0.01:
            score += 1

        label = "ChaCha20" if score >= 1 else "AES"
        X.append([length, entropy, capacity_ratio])
        y.append(label)

    model = DecisionTreeClassifier(max_depth=4, random_state=42)
    model.fit(X, y)
    return model

def agent_decide(message, capacity_bits):
    model = train_agent()
    feats = extract_features(message, capacity_bits)
    X = [[feats["length"], feats["entropy"], feats["capacity_ratio"]]]
    algo = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    classes = list(model.classes_)
    confidence = proba[classes.index(algo)] * 100

    reasons = []
    reasons.append(f"Message length: {feats['length']} characters")
    reasons.append(f"Message entropy: {feats['entropy']:.2f} bits/char "
                    f"({'high — dense/random-looking text' if feats['entropy'] > 4.2 else 'low — typical natural language'})")
    reasons.append(f"Cover capacity used: {feats['capacity_ratio']*100:.4f}% of available bits")
    if algo == "AES":
        reasons.append("Verdict: small, low-entropy payload → AES-GCM gives strong authenticated "
                        "encryption with negligible speed cost at this size")
    else:
        reasons.append("Verdict: message is long, dense, or uses significant image capacity → "
                        "ChaCha20 encrypts faster with lower CPU overhead at scale")

    return algo, confidence, reasons, feats

# =====================================================================
# Steganography codecs
# =====================================================================
def text_to_binary(text):
    binary = ''.join(format(byte, '08b') for byte in text.encode("utf-8"))
    binary += '1111111111111110'
    return binary

def binary_to_text(binary):
    payload = bytearray()
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) < 8:
            break
        payload.append(int(byte, 2))
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("The hidden data is not valid UTF-8.") from error

def hide_message(img, message):
    arr = np.array(img)
    flat = arr.flatten()
    binary_message = text_to_binary(message)
    if len(binary_message) > len(flat):
        raise ValueError(
            f"Message too long for this image: needs {len(binary_message)} bits, "
            f"but the image provides {len(flat)}."
        )
    for i in range(len(binary_message)):
        flat[i] = (int(flat[i]) & 0xFE) | int(binary_message[i])
    new_arr = flat.reshape(arr.shape)
    return Image.fromarray(new_arr.astype(np.uint8))

def extract_message(img):
    arr = np.array(img)
    flat = arr.flatten()
    binary_data = ''
    stop_marker = '1111111111111110'
    for value in flat:
        binary_data += str(value & 1)
        if binary_data[-16:] == stop_marker:
            binary_data = binary_data[:-16]
            break
    return binary_to_text(binary_data)

# =====================================================================
# Texture-aware DCT steganography
# =====================================================================
DCT_POS_A = (3, 4)
DCT_POS_B = (4, 3)
DCT_STRENGTH = 12.0

def _block_dct2(block):
    return dct(dct(block.T, norm="ortho").T, norm="ortho")

def _block_idct2(coeffs):
    return idct(idct(coeffs.T, norm="ortho").T, norm="ortho")

def texture_score(img):
    gray = np.array(img.convert("L")).astype(np.float64)
    h, w = gray.shape
    h_c, w_c = h - h % 8, w - w % 8
    if h_c == 0 or w_c == 0:
        return 0.0
    blocks = gray[:h_c, :w_c].reshape(h_c // 8, 8, w_c // 8, 8).swapaxes(1, 2)
    return float(blocks.var(axis=(2, 3)).mean())

def dct_capacity_bits(img):
    return (img.width // 8) * (img.height // 8) * 3

def choose_embedding_method(img, payload_bits_needed):
    texture_threshold = 150.0
    score = texture_score(img)
    capacity = dct_capacity_bits(img)
    if score < texture_threshold and payload_bits_needed <= capacity:
        return "DCT", score, capacity
    return "LSB", score, capacity

def _embed_bit_in_block(block, bit):
    coeffs = _block_dct2(block)
    a, b = coeffs[DCT_POS_A], coeffs[DCT_POS_B]
    if bit == "1":
        if a - b < DCT_STRENGTH:
            gap = DCT_STRENGTH - (a - b)
            a += gap / 2
            b -= gap / 2
    elif b - a < DCT_STRENGTH:
        gap = DCT_STRENGTH - (b - a)
        b += gap / 2
        a -= gap / 2
    coeffs[DCT_POS_A], coeffs[DCT_POS_B] = a, b
    return _block_idct2(coeffs)

def _extract_bit_from_block(block):
    coeffs = _block_dct2(block)
    return "1" if coeffs[DCT_POS_A] > coeffs[DCT_POS_B] else "0"

def hide_message_dct(img, message):
    arr = np.array(img).astype(np.float64)
    height, width, channels = arr.shape
    binary_message = text_to_binary(message)
    blocks_per_row, blocks_per_col = width // 8, height // 8
    total_blocks = blocks_per_row * blocks_per_col * channels
    if len(binary_message) > total_blocks:
        raise ValueError(
            f"Message too long for DCT embedding: needs {len(binary_message)} blocks, "
            f"image provides {total_blocks}."
        )
    out = arr.copy()
    bit_index = 0
    for channel in range(channels):
        for block_y in range(blocks_per_col):
            for block_x in range(blocks_per_row):
                if bit_index >= len(binary_message):
                    break
                y0, x0 = block_y * 8, block_x * 8
                block = out[y0:y0 + 8, x0:x0 + 8, channel]
                out[y0:y0 + 8, x0:x0 + 8, channel] = _embed_bit_in_block(
                    block, binary_message[bit_index]
                )
                bit_index += 1
            if bit_index >= len(binary_message):
                break
        if bit_index >= len(binary_message):
            break
    return Image.fromarray(np.clip(out, 0, 255).astype(np.uint8))

def extract_message_dct(img):
    arr = np.array(img).astype(np.float64)
    height, width, channels = arr.shape
    blocks_per_row, blocks_per_col = width // 8, height // 8
    stop_marker = "1111111111111110"
    binary_data = ""
    for channel in range(channels):
        for block_y in range(blocks_per_col):
            for block_x in range(blocks_per_row):
                y0, x0 = block_y * 8, block_x * 8
                block = arr[y0:y0 + 8, x0:x0 + 8, channel]
                binary_data += _extract_bit_from_block(block)
                if binary_data[-16:] == stop_marker:
                    return binary_to_text(binary_data[:-16])
    raise ValueError("No hidden message was found in this image (DCT).")

ZERO_WIDTH_BITS = {"0": "\u200b", "1": "\u200c"}
ZERO_WIDTH_MARKER = "\u2060\u2060"
BINARY_MARKER = b"\nSTEGO_DATA_V1\x00"

def hide_text(text, payload):
    hidden_bits = ''.join(ZERO_WIDTH_BITS[bit] for bit in text_to_binary(payload))
    return text + ZERO_WIDTH_MARKER + hidden_bits

def extract_text(text):
    if ZERO_WIDTH_MARKER not in text:
        raise ValueError("No hidden message was found in this text file.")
    hidden = text.split(ZERO_WIDTH_MARKER, 1)[1]
    bits = ''.join("0" if char == ZERO_WIDTH_BITS["0"] else "1" for char in hidden
                   if char in ZERO_WIDTH_BITS.values())
    if bits.endswith("1111111111111110"):
        bits = bits[:-16]
    return binary_to_text(bits)

def hide_binary_file(data, payload):
    payload_bytes = payload.encode("utf-8")
    return data + BINARY_MARKER + len(payload_bytes).to_bytes(4, "big") + payload_bytes

def extract_binary_file(data):
    marker_index = data.rfind(BINARY_MARKER)
    if marker_index < 0:
        raise ValueError("No hidden message was found in this media file.")
    payload_start = marker_index + len(BINARY_MARKER)
    if len(data) < payload_start + 4:
        raise ValueError("The hidden data is incomplete.")
    payload_length = int.from_bytes(data[payload_start:payload_start + 4], "big")
    payload = data[payload_start + 4:payload_start + 4 + payload_length]
    if len(payload) != payload_length:
        raise ValueError("The hidden data is incomplete.")
    return payload.decode("utf-8")

def get_payload_capacity(cover_type, data):
    if cover_type == "Image":
        return data.width * data.height * 3
    if cover_type == "Text":
        return max(len(data.encode("utf-8")) * 8, 1)
    return max(len(data) * 8, 1)

# =====================================================================
# UI
# =====================================================================
st.set_page_config(
    page_title="CipherVeil | Agentic AI steganography",
    page_icon=":material/shield_lock:",
    layout="centered",
)

css_path = Path(__file__).with_name("style.css")
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)

st.markdown(
    """
    <nav class="site-nav">
        <div class="brand-lockup"><span class="brand-shield">CV</span><strong>CipherVeil</strong><small>SECURE MEDIA TOOLS</small></div>
        <div class="nav-status"><span class="pulse-dot"></span> SYSTEM ONLINE</div>
    </nav>
    <div class="tool-intro">
        <div class="project-kicker">AGENTIC AI STEGANOGRAPHY <span class="kicker-rule"></span> CAPSTONE BUILD 01</div>
        <h1>Secure your message<br><em>inside any medium.</em></h1>
        <p class="hero-subtitle">Encrypt, conceal, and recover sensitive data through a guided media workflow.</p>
    </div>
    <div class="hero-note">Your message is encrypted, integrity-checked, and embedded inside an ordinary media file.</div>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    """
    <div class="capability-row">
        <span><b>01</b> Encrypt</span><span><b>02</b> Hide</span><span><b>03</b> Verify</span><span><b>04</b> Recover</span>
    </div>
    """,
    unsafe_allow_html=True,
)

tab1, tab2 = st.tabs(["Hide data", "Extract data"])

with tab1:
    st.subheader("Hide a secret message")
    st.caption("Select a carrier, provide your payload, and let the agent choose the encryption route.")
    cover_type = st.selectbox("Choose a cover type", ["Image", "Text", "Audio", "Video"])
    cover_extensions = {
        "Image": ["png", "jpg", "jpeg"],
        "Text": ["txt", "md", "csv"],
        "Audio": ["mp3", "wav", "ogg", "flac", "m4a"],
        "Video": ["mp4", "avi", "mov", "mkv", "webm"],
    }
    uploaded_cover = st.file_uploader(
        f"Upload a cover {cover_type.lower()} file",
        type=cover_extensions[cover_type],
    )
    message = st.text_area("Secret message")
    password = st.text_input("Password", type="password")

    if st.button("Let the agent decide and hide", type="primary", icon=":material/lock:"):
        if uploaded_cover and message and password:
            raw_cover = uploaded_cover.getvalue()
            img = Image.open(io.BytesIO(raw_cover)).convert("RGB") if cover_type == "Image" else None
            cover_data = img if img is not None else raw_cover

            with st.spinner("Agent analyzing the message and cover file..."):
                algo, confidence, reasons, feats = agent_decide(
                    message, get_payload_capacity(cover_type, cover_data)
                )

            st.markdown("### 🤖 Agent Decision")
            st.info(f"**Selected algorithm: {algo}**  (confidence: {confidence:.1f}%)")
            with st.expander("See agent's reasoning"):
                for r in reasons:
                    st.write(f"- {r}")

            msg_hash = compute_hash(message)
            encrypted = encrypt_aes(message, password) if algo == "AES" else encrypt_chacha(message, password)

            embed_method = "LSB"
            if cover_type == "Image":
                probe_payload = f"{algo}|LSB|{encrypted}|{msg_hash}"
                probe_bits = len(text_to_binary(probe_payload))
                embed_method, texture_value, dct_capacity = choose_embedding_method(img, probe_bits)
                st.markdown("### Embedding Decision")
                st.info(f"**Selected embedding: {embed_method}**  "
                        f"(texture score: {texture_value:.1f}, DCT capacity: {dct_capacity} bits)")

            payload = f"{algo}|{embed_method}|{encrypted}|{msg_hash}"

            try:
                if cover_type == "Image":
                    output_data = io.BytesIO()
                    stego_image = (hide_message_dct(img, payload)
                                   if embed_method == "DCT" else hide_message(img, payload))
                    stego_image.save(output_data, format="PNG")
                    output_bytes, output_name, mime_type = output_data.getvalue(), "stego_output.png", "image/png"
                    st.image(Image.open(io.BytesIO(output_bytes)), caption="Stego image")
                elif cover_type == "Text":
                    output_bytes = hide_text(raw_cover.decode("utf-8"), payload).encode("utf-8")
                    output_name, mime_type = "stego_output.txt", "text/plain"
                else:
                    output_bytes = hide_binary_file(raw_cover, payload)
                    suffix = Path(uploaded_cover.name).suffix or ".bin"
                    output_name, mime_type = f"stego_output{suffix}", uploaded_cover.type or "application/octet-stream"
                st.success("Message encrypted, hashed, and hidden successfully!", icon=":material/check_circle:")
                st.download_button("Download stego file", output_bytes, output_name, mime_type, icon=":material/download:")
            except ValueError as e:
                st.error(str(e))
        else:
            st.warning("Please upload an image, enter a message, and set a password.")

with tab2:
    st.subheader("Extract a hidden message")
    st.caption("Upload a carrier produced by CipherVeil and verify its message with the original password.")
    extract_type = st.selectbox("Choose the stego file type", ["Image", "Text", "Audio", "Video"], key="extract_type")
    stego_upload = st.file_uploader(
        f"Upload the stego {extract_type.lower()} file",
        type=cover_extensions[extract_type],
        key="extract",
    )
    extract_password = st.text_input("Password", type="password", key="extract_pass")

    if st.button("Extract and decrypt", type="primary", icon=":material/key:"):
        if stego_upload and extract_password:
            try:
                raw_stego = stego_upload.getvalue()
                if extract_type == "Image":
                    stego_image = Image.open(io.BytesIO(raw_stego)).convert("RGB")
                    try:
                        payload = extract_message(stego_image)
                    except Exception:
                        payload = extract_message_dct(stego_image)
                elif extract_type == "Text":
                    payload = extract_text(raw_stego.decode("utf-8"))
                else:
                    payload = extract_binary_file(raw_stego)
                fields = payload.split("|", 3)
                if len(fields) == 4:
                    algo, embed_method, encrypted, stored_hash = fields
                    st.info(f"🤖 Agent detected: **{algo}** encryption, **{embed_method}** embedding")
                else:
                    algo, encrypted, stored_hash = payload.split("|", 2)
                    st.info(f"🤖 Agent detected this was encrypted with: **{algo}**")
                decrypted = decrypt_aes(encrypted, extract_password) if algo == "AES" else decrypt_chacha(encrypted, extract_password)

                recomputed_hash = compute_hash(decrypted)
                if recomputed_hash == stored_hash:
                    st.success("Integrity verified — message is untampered.", icon=":material/verified:")
                    st.success(f"Extracted message: {decrypted}")
                else:
                    st.error("⚠️ Integrity check FAILED — message may have been tampered with!")
                    st.write(f"Extracted anyway: {decrypted}")
            except Exception:
                st.error("Wrong password, unsupported file, or corrupted hidden data.")
        else:
            st.warning("Please upload a stego image and enter the password.")
