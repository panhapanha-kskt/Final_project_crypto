import argparse
from getpass import getpass

# -------------------------
# Advanced RC4 core
# -------------------------
class AdvancedRC4:
    """
    RC4 encryption/decryption using KSA and PRGA.
    Input key may be str or bytes. Data may be bytes or str.
    """

    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode("utf-8")
        self.key = key

    def swap(self, s, i, j):
        s[i], s[j] = s[j], s[i]

    def KSA(self):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + self.key[i % len(self.key)]) % 256
            self.swap(s, i, j)
        return s

    def PRGA(self, s, length):
        i = 0
        j = 0
        keystream = []
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            self.swap(s, i, j)
            keystream.append(s[(s[i] + s[j]) % 256])
        return keystream

    def encrypt_decrypt(self, data):
        """XOR data with keystream. Accepts str or bytes, returns bytes."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        s = self.KSA()
        keystream = self.PRGA(s, len(data))
        result = bytearray([data[i] ^ keystream[i] for i in range(len(data))])
        return bytes(result)


# -------------------------
# Helpers: formatting / parsing
# -------------------------
def bytes_to_c_format(data: bytes) -> str:
    """Return C-style \\xhh representation."""
    return "".join(f"\\x{b:02x}" for b in data)


def bytes_to_python_format(data: bytes) -> str:
    """Return Python bytes([...]) literal representation."""
    return "bytes([" + ", ".join(f"0x{b:02x}" for b in data) + "])"


def parse_python_bytes_literal(data: str) -> bytes:
    """
    Parse a Python-like bytes literal beginning with b'...' or b"...".
    This function decodes escape sequences and returns raw bytes.
    """
    content = data[2:-1]
    decoded = content.encode("utf-8").decode("unicode_escape")
    return decoded.encode("latin-1")


# -------------------------
# Text operation (CLI-like)
# -------------------------
def process_text(rc4: AdvancedRC4, args):
    """
    Handles text-mode encryption & decryption behavior.
    - Accepts hex input automatically when all characters are hex and length is even.
    - Accepts Python bytes literal (b'...') format.
    - For encrypt, prints hex and \\x form.
    - For decrypt, attempts UTF-8 decode; if fails prints hex.
    """
    if not args.input:
        args.input = input("[?] Enter text: ")

    original_input = args.input
    is_python_bytes = False

    # Python bytes literal
    if original_input.startswith("b'") or original_input.startswith('b"'):
        is_python_bytes = True
        args.input = parse_python_bytes_literal(original_input)
        print("[*] Parsed Python bytes literal")

    # Detect hex (for decryption)
    clean = original_input.replace(" ", "")
    is_hex = all(c in "0123456789abcdefABCDEF" for c in clean) and len(clean) % 2 == 0

    if is_hex and not is_python_bytes:
        try:
            args.input = bytes.fromhex(clean)
            print("[*] Converted hex to bytes")
        except Exception:
            # keep args.input unchanged if conversion fails
            pass

    # Encrypt mode
    if args.mode == "encrypt":
        result = rc4.encrypt_decrypt(args.input)
        print_output(result, args.output_format, args.output, "encrypt")
        return

    # Decrypt mode
    try:
        encrypted_data = bytes.fromhex(clean)
    except Exception:
        encrypted_data = args.input.encode("utf-8")

    result = rc4.encrypt_decrypt(encrypted_data)
    print_output(result, args.output_format, args.output, "decrypt")


# -------------------------
# Output formatting & saving
# -------------------------
def print_output(data: bytes, format_type: str, output_file: str, mode: str):
    """Print results (friendly) and optionally save to file."""
    if mode == "encrypt":
        print("Encrypted (hex):", data.hex())
        print("Encrypted (\\x):", bytes_to_c_format(data))
    else:
        try:
            print("Decrypted text:", data.decode("utf-8"))
        except Exception:
            print("Decrypted (hex):", data.hex())

    if output_file:
        with open(output_file, "wb") as f:
            f.write(data)
        print(f"Saved to {output_file}")


# -------------------------
# CLI-style main (if run standalone)
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="RC4 Text Encryption Tool")
    parser.add_argument("-m", "--mode", required=True, choices=["encrypt", "decrypt"])
    parser.add_argument("-i", "--input")
    parser.add_argument("-k", "--key")
    parser.add_argument("-o", "--output")
    parser.add_argument("--output-format", choices=["raw", "hex", "base64", "c", "python"], default="hex")

    args = parser.parse_args()

    if not args.key:
        args.key = getpass("[?] Key: ")

    rc4 = AdvancedRC4(args.key)
    process_text(rc4, args)


if __name__ == "__main__":
    main()
