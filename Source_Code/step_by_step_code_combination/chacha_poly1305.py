import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

def encrypt_message(plaintext, header=b"header"):
    """Encrypt a message using ChaCha20-Poly1305"""
    # Convert string to bytes if needed
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(header, str):
        header = header.encode('utf-8')
    
    # Generate random key
    key = get_random_bytes(32)
    
    # Create cipher and encrypt
    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Prepare JSON output
    jk = ['nonce', 'header', 'ciphertext', 'tag', 'key']
    jv = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag, key)]
    result = json.dumps(dict(zip(jk, jv)), indent=2)
    
    return result

def decrypt_message(encrypted_json):
    """Decrypt a ChaCha20-Poly1305 encrypted message"""
    try:
        data = json.loads(encrypted_json)
        
        # Decode from base64
        nonce = b64decode(data['nonce'])
        header = b64decode(data['header'])
        ciphertext = b64decode(data['ciphertext'])
        tag = b64decode(data['tag'])
        key = b64decode(data['key'])
        
        # Decrypt
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption failed: {str(e)}"

def main():
    print("=== ChaCha20-Poly1305 Encryption Tool ===\n")
    
    while True:
        print("\nOptions:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            plaintext = input("\nEnter the message to encrypt: ")
            header = input("Enter header/additional data (press Enter for default 'header'): ").strip()
            
            if not header:
                header = "header"
            
            result = encrypt_message(plaintext, header)
            print("\n=== Encrypted Result ===")
            print(result)
            print("\nSave this JSON to decrypt later!")
            
        elif choice == '2':
            print("\nPaste the encrypted JSON (end with empty line):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            
            encrypted_json = '\n'.join(lines)
            plaintext = decrypt_message(encrypted_json)
            print("\n=== Decrypted Message ===")
            print(plaintext)
            
        elif choice == '3':
            print("\nGoodbye!")
            break
        else:
            print("\nInvalid choice. Please try again.")

if __name__ == "__main__":
    main()
