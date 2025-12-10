# triple_enc.py
"""
Secure multilayer encryption flow (patched).

Replaces custom AES implementation with PyCryptodome AES (CBC for data,
AES-GCM for key-wrapping) and uses PBKDF2 for deriving a wrapping key from
a user passphrase. Fixes blowfish key storage, RC4 key storage, and avoids
saving ChaCha20 key in plaintext.

Flow (Encrypt):
 1) ChaCha20-Poly1305 -> JSON (nonce,header,ciphertext,tag)
 2) Base64(JSON) -> AES-256-CBC (random data_key + iv)  (data encryption)
 3) Blowfish-CBC encrypt AES ciphertext using blowfish key (user-provided)
 4) RC4 encrypt Blowfish ciphertext using RC4 key (user-provided)
 5) Save wrapped keys (wrapped with AES-GCM using a key derived from passphrase)

Flow (Decrypt):
 Reverse the above using the passphrase to unwrap keys.

Notes:
 - Requires PyCryptodome: pip install pycryptodome
 - Session file contains: salt + wrapped blobs (base64 JSON)
"""

import os
import json
import base64
from base64 import b64encode, b64decode
from typing import Tuple

from getpass import getpass
from Crypto.Random import get_random_bytes
from Crypto.Cipher import Blowfish, AES as PyAES, ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2

# Rich is optional but used in the UI flows (keeps your UI style)
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich.box import ROUNDED

console = Console()

# Constants for PBKDF2
PBKDF2_ITERATIONS = 200_000
PBKDF2_KEY_LEN = 32  # 256-bit wrapping key
PBKDF2_SALT_LEN = 16

# Session file path (same folder structure you used)
SESSION_FILE = "Source_Code\\all_session\\session_wrapped.json"
CIPHERTEXT_FILE = "Source_Code\\all_session\\ciphertext.hex"

# RC4 engine (kept from your rc4_addingx module)
from rc4_addingx import AdvancedRC4


# ---------------------------
# Helpers: PKCS7 padding for AES-CBC
# ---------------------------
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Invalid PKCS7 padding (empty input)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]


# ---------------------------
# AES-CBC encryption (data)
# ---------------------------
def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = PyAES.new(key, PyAES.MODE_CBC, iv)
    pt = pkcs7_pad(plaintext, 16)
    return cipher.encrypt(pt)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of AES block size")
    cipher = PyAES.new(key, PyAES.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)
    return pkcs7_unpad(pt)


# ---------------------------
# Key wrapping with AES-GCM
# ---------------------------
def derive_wrapping_key(passphrase: str, salt: bytes) -> bytes:
    # Use PBKDF2 to derive a symmetric key to wrap keys
    return PBKDF2(passphrase.encode("utf-8"), salt, dkLen=PBKDF2_KEY_LEN, count=PBKDF2_ITERATIONS)


def wrap_with_aes_gcm(wrap_key: bytes, plaintext: bytes) -> dict:
    # Returns dict with nonce, ciphertext, tag (all base64 encoded)
    nonce = get_random_bytes(12)
    cipher = PyAES.new(wrap_key, PyAES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": b64encode(nonce).decode(), "ct": b64encode(ct).decode(), "tag": b64encode(tag).decode()}


def unwrap_with_aes_gcm(wrap_key: bytes, wrapped: dict) -> bytes:
    nonce = b64decode(wrapped["nonce"])
    ct = b64decode(wrapped["ct"])
    tag = b64decode(wrapped["tag"])
    cipher = PyAES.new(wrap_key, PyAES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


# ---------------------------
# ChaCha20 helpers (unchanged logic, but keys protected)
# ---------------------------
def encrypt_message_chacha(plaintext: bytes, header: bytes = b"header") -> Tuple[str, bytes]:
    cipher = ChaCha20_Poly1305.new(key=get_random_bytes(32))
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    result = {
        "nonce": b64encode(cipher.nonce).decode(),
        "header": b64encode(header).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
        "tag": b64encode(tag).decode(),
    }
    return json.dumps(result, indent=2), b64decode(b64encode(cipher.nonce + ciphertext + tag))  # not used but kept minimal


def encrypt_message_chacha_with_key(plaintext: bytes, header: bytes, key: bytes) -> Tuple[str, bytes]:
    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    result = {
        "nonce": b64encode(cipher.nonce).decode(),
        "header": b64encode(header).decode(),
        "ciphertext": b64encode(ciphertext).decode(),
        "tag": b64encode(tag).decode(),
    }
    return json.dumps(result, indent=2), key


def decrypt_message_chacha(encrypted_json: str, key: bytes) -> str:
    data = json.loads(encrypted_json)
    nonce = b64decode(data["nonce"])
    header = b64decode(data["header"])
    ciphertext = b64decode(data["ciphertext"])
    tag = b64decode(data["tag"])
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


# ---------------------------
# Blowfish wrappers (unchanged except no key mangling)
# ---------------------------
def blowfish_encrypt_full(data: bytes, key: bytes) -> bytes:
    # Uses PKCS#7 style padding specific to block size (Blowfish.block_size)
    bs = Blowfish.block_size
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    padding_len = bs - (len(data) % bs)
    data_padded = data + bytes([padding_len]) * padding_len
    return cipher.iv + cipher.encrypt(data_padded)


def blowfish_decrypt_full(data: bytes, key: bytes) -> bytes:
    bs = Blowfish.block_size
    if len(data) < bs:
        raise ValueError("Ciphertext too short for Blowfish")
    iv = data[:bs]
    ct = data[bs:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    pt_padded = cipher.decrypt(ct)
    pad_len = pt_padded[-1]
    return pt_padded[:-pad_len]


# ---------------------------
# Multilayer encrypt/decrypt flows with secure wrapping
# ---------------------------
def multilayer_encrypt_flow():
    console.print(Panel("ChaCha20 → AES-CBC → Blowfish → RC4 (secure patch)", title="[bold cyan]MULTILAYER ENCRYPTION[/bold cyan]", border_style="bright_blue", box=ROUNDED))

    txt = Prompt.ask("[bold green]Enter plaintext to encrypt[/bold green]")
    if not txt:
        console.print("[bold red]No input provided.[/bold red]")
        return

    # Blowfish key provided by user (text)
    blowfish_key_input = Prompt.ask("[bold yellow]Enter Blowfish key (4–56 bytes)[/bold yellow]").encode("utf-8")
    if len(blowfish_key_input) < 4 or len(blowfish_key_input) > 56:
        console.print("[bold red]Blowfish key must be between 4 and 56 bytes.[/bold red]")
        return

    # RC4 key provided by user
    rc4_key_input = Prompt.ask("[bold magenta]Enter RC4 key (min 5 bytes)[/bold magenta]").strip().encode("utf-8")
    if len(rc4_key_input) < 5:
        console.print("[bold red]RC4 key must be at least 5 bytes.[/bold red]")
        return

    # Ask for passphrase that will protect stored session keys (mandatory)
    console.print("[bold cyan]You will be asked to choose a passphrase to protect stored session keys.[/bold cyan]")
    passphrase = getpass("[?] Enter passphrase for session storage: ").strip()
    if not passphrase:
        console.print("[bold red]Passphrase is required to securely store keys.[/bold red]")
        return

    # 1) ChaCha20-Poly1305
    header = b"multilayer"
    chacha_key = get_random_bytes(32)
    chacha_json, _ = encrypt_message_chacha_with_key(txt.encode("utf-8"), header, chacha_key)

    # 2) AES (random key + IV) for data encryption
    data_aes_key = get_random_bytes(32)  # AES-256
    data_iv = get_random_bytes(16)
    b64_json = b64encode(chacha_json.encode("utf-8"))
    aes_ciphertext = aes_cbc_encrypt(b64_json, data_aes_key, data_iv)

    # 3) Blowfish encrypt AES ciphertext
    blowfish_ciphertext = blowfish_encrypt_full(aes_ciphertext, blowfish_key_input)

    # 4) RC4 encrypt Blowfish ciphertext
    rc4 = AdvancedRC4(rc4_key_input)
    final_ciphertext = rc4.encrypt_decrypt(blowfish_ciphertext)

    # Wrap keys with passphrase-derived wrapping key
    salt = get_random_bytes(PBKDF2_SALT_LEN)
    wrapping_key = derive_wrapping_key(passphrase, salt)

    wrapped = {
        "data_aes_key": wrap_with_aes_gcm(wrapping_key, data_aes_key),
        "data_iv": wrap_with_aes_gcm(wrapping_key, data_iv),
        "chacha_key": wrap_with_aes_gcm(wrapping_key, chacha_key),
        "blowfish_key": wrap_with_aes_gcm(wrapping_key, blowfish_key_input),
        "rc4_key": wrap_with_aes_gcm(wrapping_key, rc4_key_input),
    }

    session_struct = {"salt": b64encode(salt).decode(), "wrapped": wrapped}
    os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
    with open(SESSION_FILE, "w") as f:
        json.dump(session_struct, f, indent=2)

    # Save final ciphertext hex
    os.makedirs(os.path.dirname(CIPHERTEXT_FILE), exist_ok=True)
    with open(CIPHERTEXT_FILE, "w") as f:
        f.write(final_ciphertext.hex())

    console.print(Panel(Text(final_ciphertext.hex(), style="bold bright_green"), title="[bold cyan]RESULT (hex)[/bold cyan]", border_style="bright_blue"))


def multilayer_decrypt_flow():
    console.print(Panel("RC4 → Blowfish → AES-CBC → ChaCha20 (secure patch)", title="[bold cyan]MULTILAYER DECRYPTION[/bold cyan]", border_style="bright_blue", box=ROUNDED))

    if not os.path.exists(SESSION_FILE):
        console.print(f"[bold red]ERROR:[/bold red] Session file {SESSION_FILE} not found.")
        return

    passphrase = getpass("[?] Enter passphrase to unlock session: ").strip()
    if not passphrase:
        console.print("[bold red]Passphrase required.[/bold red]")
        return

    # Load wrapped session
    with open(SESSION_FILE, "r") as f:
        session_struct = json.load(f)

    salt = b64decode(session_struct["salt"])
    wrapping_key = derive_wrapping_key(passphrase, salt)

    try:
        wrapped = session_struct["wrapped"]
        data_aes_key = unwrap_with_aes_gcm(wrapping_key, wrapped["data_aes_key"])
        data_iv = unwrap_with_aes_gcm(wrapping_key, wrapped["data_iv"])
        chacha_key = unwrap_with_aes_gcm(wrapping_key, wrapped["chacha_key"])
        blowfish_key_input = unwrap_with_aes_gcm(wrapping_key, wrapped["blowfish_key"])
        rc4_key_input = unwrap_with_aes_gcm(wrapping_key, wrapped["rc4_key"])
    except Exception as e:
        console.print(f"[bold red]Failed to unwrap session keys: {e}[/bold red]")
        return

    # Get ciphertext hex (ask user or use saved file)
    user_input = Prompt.ask("[bold green]Paste ciphertext hex (or press Enter to use stored ciphertext.hex)[/bold green]").strip()
    if user_input:
        cthex = user_input
    else:
        if not os.path.exists(CIPHERTEXT_FILE):
            console.print(f"[bold red]ERROR:[/bold red] No stored ciphertext file at {CIPHERTEXT_FILE}.")
            return
        with open(CIPHERTEXT_FILE, "r") as f:
            cthex = f.read().strip()

    try:
        final_ciphertext = bytes.fromhex(cthex)
    except Exception:
        console.print("[bold red]Invalid hex input.[/bold red]")
        return

    # RC4 decrypt
    try:
        rc4 = AdvancedRC4(rc4_key_input)
        blowfish_layer = rc4.encrypt_decrypt(final_ciphertext)
    except Exception as e:
        console.print(f"[bold red]RC4 decryption failed: {e}[/bold red]")
        return

    # Blowfish decrypt
    try:
        aes_ciphertext = blowfish_decrypt_full(blowfish_layer, blowfish_key_input)
    except Exception as e:
        console.print(f"[bold red]Blowfish decryption failed: {e}[/bold red]")
        return

    # AES-CBC decrypt -> gets base64 JSON
    try:
        decrypted_b64 = aes_cbc_decrypt(aes_ciphertext, data_aes_key, data_iv)
        chacha_json = base64.b64decode(decrypted_b64).decode("utf-8")
    except Exception as e:
        console.print(f"[bold red]AES-CBC decryption failed: {e}[/bold red]")
        return

    # ChaCha20 decrypt
    try:
        plaintext = decrypt_message_chacha(chacha_json, chacha_key)
    except Exception as e:
        console.print(f"[bold red]ChaCha20 decryption failed: {e}[/bold red]")
        return

    console.print(Panel(Text(plaintext, style="bold bright_green"), title="[bold cyan]DECRYPTED PLAINTEXT[/bold cyan]", border_style="bright_blue"))


# Optional CLI entrypoint
def main():
    print("=== Secure multilayer encryption (patched) ===")
    while True:
        print("\nOptions:")
        print("1. Multilayer Encrypt")
        print("2. Multilayer Decrypt")
        print("3. Exit")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            multilayer_encrypt_flow()
        elif choice == "2":
            multilayer_decrypt_flow()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
