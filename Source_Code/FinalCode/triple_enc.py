import json
import os
import sys
import base64
from base64 import b64encode, b64decode
from typing import Tuple, List

from Crypto.Random import get_random_bytes
from Crypto.Cipher import Blowfish, AES, ChaCha20_Poly1305

# >>> RC4 ADDED <<<
from rc4_addingx import AdvancedRC4

# ------------------------------------------------------------
# AES constants for AES-256
# ------------------------------------------------------------
Nb = 4
Nk = 8  # AES-256
Nr = 14

# ------------------------------------------------------------
# S-Box + inverse
# ------------------------------------------------------------
s_box = [
    [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
    [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0],
    [0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15],
    [0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75],
    [0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84],
    [0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf],
    [0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8],
    [0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2],
    [0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73],
    [0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb],
    [0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79],
    [0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08],
    [0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a],
    [0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e],
    [0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf],
    [0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
]

inv_s_box = [[0]*16 for _ in range(16)]
for i in range(16):
    for j in range(16):
        inv_s_box[s_box[i][j] >> 4][s_box[i][j] & 0x0F] = (i << 4) | j

# ------------------------------------------------------------
# Utility (GF, state conversions)
# ------------------------------------------------------------
def xtime(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1)

def gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = xtime(a)
        b >>= 1
    return res & 0xFF

def state_from_bytes(block: bytes) -> List[List[int]]:
    return [list(block[i::4]) for i in range(4)]

def bytes_from_state(state: List[List[int]]) -> bytes:
    return bytes(state[row][col] for col in range(4) for row in range(4))

# ------------------------------------------------------------
# AES round functions
# ------------------------------------------------------------
def sub_bytes(state):
    for c in range(4):
        for r in range(4):
            v = state[c][r]
            state[c][r] = s_box[v >> 4][v & 0x0F]

def inv_sub_bytes(state):
    for c in range(4):
        for r in range(4):
            v = state[c][r]
            state[c][r] = inv_s_box[v >> 4][v & 0x0F]

def shift_rows(state):
    for r in range(1, 4):
        row = [state[c][r] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            state[c][r] = row[c]

def inv_shift_rows(state):
    for r in range(1, 4):
        row = [state[c][r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            state[c][r] = row[c]

def mix_columns(state):
    for c in range(4):
        a = state[c]
        state[c] = [
            gf_mul(a[0],2) ^ gf_mul(a[1],3) ^ a[2] ^ a[3],
            a[0] ^ gf_mul(a[1],2) ^ gf_mul(a[2],3) ^ a[3],
            a[0] ^ a[1] ^ gf_mul(a[2],2) ^ gf_mul(a[3],3),
            gf_mul(a[0],3) ^ a[1] ^ a[2] ^ gf_mul(a[3],2),
        ]

def inv_mix_columns(state):
    for c in range(4):
        a = state[c]
        state[c] = [
            gf_mul(a[0],14) ^ gf_mul(a[1],11) ^ gf_mul(a[2],13) ^ gf_mul(a[3],9),
            gf_mul(a[0],9)  ^ gf_mul(a[1],14) ^ gf_mul(a[2],11) ^ gf_mul(a[3],13),
            gf_mul(a[0],13) ^ gf_mul(a[1],9)  ^ gf_mul(a[2],14) ^ gf_mul(a[3],11),
            gf_mul(a[0],11) ^ gf_mul(a[1],13) ^ gf_mul(a[2],9)  ^ gf_mul(a[3],14),
        ]

def add_round_key(state, round_key):
    for c in range(4):
        for r in range(4):
            state[c][r] ^= round_key[c][r]

# ------------------------------------------------------------
# Key expansion (AES-256)
# ------------------------------------------------------------
Rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def expand_key(key: bytes) -> List[List[List[int]]]:
    words = [list(key[i:i+4]) for i in range(0, 32, 4)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = words[i - 1].copy()
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [s_box[b >> 4][b & 0x0F] for b in temp]
            temp[0] ^= Rcon[i // Nk]
        elif i % Nk == 4:
            temp = [s_box[b >> 4][b & 0x0F] for b in temp]
        words.append([(words[i - Nk][j] ^ temp[j]) & 0xFF for j in range(4)])

    round_keys = []
    for r in range(Nr + 1):
        start = r * 4
        key_state = [[words[start + c][r2] for r2 in range(4)] for c in range(4)]
        round_keys.append(key_state)
    return round_keys

# ------------------------------------------------------------
# Block encrypt/decrypt
# ------------------------------------------------------------
def encrypt_block(block: bytes, round_keys):
    state = state_from_bytes(block)
    add_round_key(state, round_keys[0])

    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[Nr])
    return bytes_from_state(state)

def decrypt_block(block: bytes, round_keys):
    state = state_from_bytes(block)
    add_round_key(state, round_keys[Nr])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for rnd in range(Nr - 1, 0, -1):
        add_round_key(state, round_keys[rnd])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, round_keys[0])
    return bytes_from_state(state)


# ------------------------------------------------------------
# CBC mode and padding
# ------------------------------------------------------------
def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data in unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    data = pad(data)
    rk = expand_key(key)
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes([data[i+j] ^ prev[j] for j in range(16)])
        c = encrypt_block(block, rk)
        out += c
        prev = c
    return out

def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
    rk = expand_key(key)
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        d = decrypt_block(data[i:i+16], rk)
        out += bytes([d[j] ^ prev[j] for j in range(16)])
        prev = data[i:i+16]
    return unpad(out)

# ------------------------------------------------------------
# Blowfish Encryption/Decryption
# ------------------------------------------------------------
def blowfish_encrypt(data: bytes, key: bytes) -> bytes:
    bs = Blowfish.block_size
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    plen = bs - len(data) % bs
    padding = bytes([plen] * plen)
    encrypted = cipher.iv + cipher.encrypt(data + padding)
    return encrypted

def blowfish_decrypt(data: bytes, key: bytes) -> bytes:
    bs = Blowfish.block_size
    if len(data) < bs:
        raise ValueError("Ciphertext too short")
    iv = data[:bs]
    cipher_data = data[bs:]
    decipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted = decipher.decrypt(cipher_data)
    padding_length = decrypted[-1]
    return decrypted[:-padding_length]

# ------------------------------------------------------------
# JSON <-> Base64 helpers
# ------------------------------------------------------------
def json_to_base64(json_text: str) -> str:
    return base64.b64encode(json_text.encode()).decode()

def base64_to_json(b64: str) -> str:
    return base64.b64decode(b64.encode()).decode()

# ------------------------------------------------------------
# Session persistence helpers
# ------------------------------------------------------------
SESSION_FILE = "Source_Code\\all_session\\aes_session.json"
BLOWFISH_KEY_FILE = "Source_Code\\all_session\\blowfish_key.bin"

def save_session(filename: str, key: bytes, iv: bytes):
    with open(filename, "w") as f:
        json.dump({"key": key.hex(), "iv": iv.hex()}, f)

def load_session(filename: str) -> Tuple[bytes, bytes]:
    with open(filename, "r") as f:
        d = json.load(f)
    return bytes.fromhex(d["key"]), bytes.fromhex(d["iv"])

def save_blowfish_key(filename: str, key: bytes):
    with open(filename, "wb") as f:
        f.write(key)

def load_blowfish_key(filename: str) -> bytes:
    with open(filename, "rb") as f:
        return f.read()

# ------------------------------------------------------------
# CLI behavior and helper functions for ChaCha20 layer
# ------------------------------------------------------------
def encrypt_flow():
    print("\nEnter JSON message (single line):")
    txt = input().strip()
    if not txt:
        print("No input provided.")
        return

    try:
        json.loads(txt)
    except Exception:
        print("Warning: input is not valid JSON. Proceeding anyway.")

    b64_json = json_to_base64(txt).encode()
    key = os.urandom(32)
    iv = os.urandom(16)
    ciphertext = aes_cbc_encrypt(b64_json, key, iv)
    save_session(SESSION_FILE, key, iv)

    print("\n--- ENCRYPTION RESULT ---")
    print("Ciphertext (hex):")
    print(ciphertext.hex())

    with open("Source_Code\\all_session\\ciphertext.hex", "w") as f:
        f.write(ciphertext.hex())

def decrypt_flow():
    if not os.path.exists(SESSION_FILE):
        print(f"ERROR: Session file {SESSION_FILE} not found.")
        print("You must encrypt first to generate key & IV.")
        return

    key, iv = load_session(SESSION_FILE)

    cthex = input("Enter ciphertext (hex): ").strip()
    try:
        ciphertext = bytes.fromhex(cthex)
    except Exception:
        print("Ciphertext is not valid hex.")
        return

    try:
        decrypted = aes_cbc_decrypt(ciphertext, key, iv)
        original_json = base64_to_json(decrypted.decode())
        print("\n--- DECRYPTION RESULT ---")
        print(original_json)
    except Exception as e:
        print("Decryption failed:", e)

    fname = "ciphertext.hex"
    try:
        with open(fname, "r") as f:
            cthex = f.read().strip()
    except Exception as e:
        print(f"Failed to read {fname}: {e}")
        return

    try:
        ciphertext = bytes.fromhex(cthex)
    except Exception as e:
        print("Ciphertext is not valid hex.")
        return

    try:
        decrypted = aes_cbc_decrypt(ciphertext, key, iv)
        original_json = base64_to_json(decrypted.decode())
        print("\n--- DECRYPTION RESULT ---")
        print(original_json)
    except Exception as e:
        print("Decryption failed:", e)

# ------------------------------------------------------------
# ChaCha20 message helper functions
# ------------------------------------------------------------
def encrypt_message(plaintext, header=b"header"):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(header, str):
        header = header.encode('utf-8')

    key = get_random_bytes(32)
    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    jk = ['nonce', 'header', 'ciphertext', 'tag']
    jv = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag)]
    result = json.dumps(dict(zip(jk, jv)), indent=2)
    return result, key

def decrypt_message(encrypted_json, key: bytes):
    try:
        data = json.loads(encrypted_json)
        nonce = b64decode(data['nonce'])
        header = b64decode(data['header'])
        ciphertext = b64decode(data['ciphertext'])
        tag = b64decode(data['tag'])
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# ------------------------------------------------------------
# Multilayer pipeline: encrypt / decrypt flows
# ------------------------------------------------------------
RC4_KEY_FILE = "Source_Code\\all_session\\rc4_key.bin"
def multilayer_encrypt_flow():
    """
    Full multilayer encryption:
    1. ChaCha20-Poly1305 → JSON output
    2. JSON → Base64 → AES-256-CBC
    3. AES output → Blowfish-CBC
    4. Blowfish → RC4   (ADDED)
    """
    print("\nEnter plaintext to encrypt (ChaCha20 → AES → Blowfish → RC4):")
    txt = input().strip()
    if not txt:
        print("No input provided.")
        return

    print("\nEnter Blowfish key (4-56 bytes):")
    blowfish_key_input = input().strip().encode()
    if len(blowfish_key_input) < 4 or len(blowfish_key_input) > 56:
        print("Blowfish key must be between 4 and 56 bytes.")
        return

    # Step 1: ChaCha20
    chacha_json, chacha_key = encrypt_message(txt)
    b64_json = json_to_base64(chacha_json).encode()

    # Step 2: AES
    key = os.urandom(32)
    iv = os.urandom(16)
    ciphertext = aes_cbc_encrypt(b64_json, key, iv)

    # Step 3: Blowfish
    blowfish_ciphertext = blowfish_encrypt(ciphertext, blowfish_key_input)

    # >>> RC4 ADDED HERE <<<
    print("\nEnter RC4 key:")
    rc4_key_input = input().strip()
    # Save files (exact behavior preserved)
    with open(RC4_KEY_FILE, "wb") as f:
        encrypt_key = aes_cbc_encrypt(rc4_key_input.encode(), key, iv)
        f.write(encrypt_key)  # save the encryption of RC4 key


    rc4_tool = AdvancedRC4(rc4_key_input)
    final_ciphertext = rc4_tool.encrypt_decrypt(blowfish_ciphertext)

   

    save_session(SESSION_FILE, key, iv)
    #Encrypt blowfish bin file
    encrypt_key = aes_cbc_encrypt(blowfish_key_input, key, iv)
    save_blowfish_key(BLOWFISH_KEY_FILE, encrypt_key)  

    with open("Source_Code\\all_session\\chacha_key.bin", "wb") as f:
        f.write(chacha_key)

    print("\n--- MULTILAYER ENCRYPTION RESULT ---")
    print(final_ciphertext.hex())

    with open("Source_Code\\all_session\\ciphertext.hex", "w") as f:
        f.write(final_ciphertext.hex())

    with open("Source_Code\\all_session\\chacha_output.json", "w") as f:
        f.write(chacha_json)

def multilayer_decrypt_flow():
    """
    Full multilayer decryption:
    1. RC4 → Blowfish
    2. Blowfish → AES
    3. AES → Base64 → JSON
    4. ChaCha20
    """
    if not os.path.exists(SESSION_FILE):
        print(f"ERROR: Session file {SESSION_FILE} not found.")
        return
    
    key, iv = load_session(SESSION_FILE)

    # === DECRYPT THE ENCRYPTED BLOWFISH KEY FILE ===
    try:
        encrypted_bf_key = load_blowfish_key(BLOWFISH_KEY_FILE)
        real_blowfish_key = aes_cbc_decrypt(encrypted_bf_key, key, iv)
    except Exception as e:
        print("Failed to decrypt Blowfish key file:", e)
        return


    # === DECRYPT THE ENCRYPTED RC4 KEY FILE ===
    try:
        encrypted_rc4_key = open(RC4_KEY_FILE, "rb").read()
        real_rc4_key = aes_cbc_decrypt(encrypted_rc4_key, key, iv).decode()
    except Exception as e:
        print("Failed to decrypt RC4 key file:", e)
        return
    # === END DECRYPTION OF RC4 KEY FILE ===

    try:
        with open("Source_Code\\all_session\\chacha_key.bin", "rb") as f:
            chacha_key = f.read()
    except FileNotFoundError:
        print("ERROR: chacha_key.bin missing")
        return

    print("Enter Blowfish key to decrypt:")
    blowfish_key_input = real_blowfish_key
    if len(blowfish_key_input) < 4 or len(blowfish_key_input) > 56:
        print("Blowfish key must be between 4 and 56 bytes.")
        return

    print("Press Enter to use ciphertext.hex or Paste your ciphertext:")
    user_input = input().strip()
    if user_input:
        cthex = user_input
    else:
        with open("Source_Code\\all_session\\ciphertext.hex", "r") as f:
            cthex = f.read().strip()

    try:
        final_ciphertext = bytes.fromhex(cthex)
    except:
        print("Invalid hex.")
        return

    # >>> RC4 DECRYPTION ADDED HERE <<<
    try:
        if not os.path.exists(RC4_KEY_FILE):
            print("Missing rc4_key.bin")
            return
        rc4_key = open(RC4_KEY_FILE, "rb").read().decode(errors='ignore')
        rc4_tool = AdvancedRC4(real_rc4_key)
        blowfish_layer = rc4_tool.encrypt_decrypt(final_ciphertext)
    except Exception as e:
        print("RC4 Decryption failed:", e)
        return

    # Step 2: Blowfish decrypt
    try:
        aes_ciphertext = blowfish_decrypt(blowfish_layer, blowfish_key_input)
    except Exception as e:
        print("Blowfish Decryption failed:", e)
        return

    # Step 3: AES
    try:
        decrypted = aes_cbc_decrypt(aes_ciphertext, key, iv)
        chacha_json = base64_to_json(decrypted.decode())
    except Exception as e:
        print("AES Decryption failed:", e)
        return

    # Step 4: ChaCha20
    try:
        plaintext = decrypt_message(chacha_json, chacha_key)
        if isinstance(plaintext, str) and plaintext.startswith("Decryption failed"):
            print(plaintext)
            return
    except Exception as e:
        print("ChaCha20 Decryption failed:", e)
        return

    print("\n--- MULTILAYER DECRYPTION RESULT ---")
    print(plaintext)

# ------------------------------------------------------------
# Entrypoint / Main
# ------------------------------------------------------------
def main():
    print("=== AES-256-CBC Encryption Tool ===\n")
    while True:
        print("\nOptions:")
        print("1. Multilayer Encrypt (ChaCha20 → AES → Blowfish → RC4)")
        print("2. Multilayer Decrypt (RC4 → Blowfish → AES → ChaCha20)")
        print("3. Exit")

        choice = input("\nEnter your choice (1-3): ").strip()
        if choice == '1':
            multilayer_encrypt_flow()
        elif choice == '2':
            multilayer_decrypt_flow()
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
