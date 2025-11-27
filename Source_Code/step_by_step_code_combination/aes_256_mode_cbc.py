from typing import Tuple, List
import os
import json
import base64
import sys

# ------------------------------------------------------------
# AES CONSTANTS for AES-256
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
    # AES state is columns of 4 bytes each; block is 16 bytes
    return [list(block[i::4]) for i in range(4)]

def bytes_from_state(state: List[List[int]]) -> bytes:
    # read column-major (col 0 rows 0..3, col1 rows 0..3, ...)
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
    # produce round keys as list of 4x4 states (columns)
    words = [list(key[i:i+4]) for i in range(0, 32, 4)]  # 8 words for AES-256
    for i in range(Nk, Nb * (Nr + 1)):
        temp = words[i - 1].copy()
        if i % Nk == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [s_box[b >> 4][b & 0x0F] for b in temp]
            temp[0] ^= Rcon[i // Nk]
        elif i % Nk == 4:
            # For AES-256, apply S-box to every byte when i % Nk == 4
            temp = [s_box[b >> 4][b & 0x0F] for b in temp]
        words.append([(words[i - Nk][j] ^ temp[j]) & 0xFF for j in range(4)])

    round_keys = []
    for r in range(Nr + 1):
        start = r * 4
        # build 4 columns of 4 bytes
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
# JSON <-> Base64 helpers
# ------------------------------------------------------------
def json_to_base64(json_text: str) -> str:
    return base64.b64encode(json_text.encode()).decode()

def base64_to_json(b64: str) -> str:
    return base64.b64decode(b64.encode()).decode()

# ------------------------------------------------------------
# Session persistence helpers
# ------------------------------------------------------------
SESSION_FILE = "aes_session.json"

def save_session(filename: str, key: bytes, iv: bytes):
    with open(filename, "w") as f:
        json.dump({"key": key.hex(), "iv": iv.hex()}, f)

def load_session(filename: str) -> Tuple[bytes, bytes]:
    with open(filename, "r") as f:
        d = json.load(f)
    return bytes.fromhex(d["key"]), bytes.fromhex(d["iv"])

# ------------------------------------------------------------
# CLI behavior
# ------------------------------------------------------------
def encrypt_flow():
    print("\nEnter JSON message (single line):")
    txt = input().strip()

    if not txt:
        print("No input provided.")
        return

    # Optional JSON validation
    try:
        json.loads(txt)
    except Exception:
        print("Warning: input is not valid JSON. Proceeding anyway.")

    # Convert JSON → Base64 → bytes
    b64_json = json_to_base64(txt).encode()

    # AES-256 key + IV
    key = os.urandom(32)
    iv = os.urandom(16)

    # Encrypt
    ciphertext = aes_cbc_encrypt(b64_json, key, iv)

    # Save key+iv for later decryption
    save_session(SESSION_FILE, key, iv)

    # Output
    print("\n--- ENCRYPTION RESULT ---")
    print("Ciphertext (hex):")
    print(ciphertext.hex())

    # Automatically save WITHOUT asking
    output_file = "ciphertext.hex"
    with open(output_file, "w") as f:
        f.write(ciphertext.hex())



def decrypt_flow():
    # Always load session automatically
    if not os.path.exists(SESSION_FILE):
        print(f"ERROR: Session file {SESSION_FILE} not found.")
        print("You must encrypt first to generate key & IV.")
        return

    key, iv = load_session(SESSION_FILE)
    

    # Direct ciphertext input only
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
        # decrypted is base64-encoded JSON
        original_json = base64_to_json(decrypted.decode())
        print("\n--- DECRYPTION RESULT ---")
        print(original_json)
    except Exception as e:
        print("Decryption failed:", e)

def main():
    print("=== AES-256-CBC JSON TOOL ===")
    print("1) Encrypt JSON")
    print("2) Decrypt JSON (hex input)")
    choice = input("Select option (1/2): ").strip()
    if choice == "1":
        encrypt_flow()
    elif choice == "2":
        decrypt_flow()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
