from Crypto.Cipher import Blowfish
import binascii  # For hex conversions

# Blowfish block size
bs = Blowfish.block_size

# --- USER INPUT ---
action = input("Choose action (encrypt/decrypt): ").strip().lower()

# Ask the user for their own private key
user_key = input("Enter your private key: ").encode()

# Validate key
if len(user_key) == 0:
    print("Key cannot be empty.")
    exit(1)

if len(user_key) < 4 or len(user_key) > 56:
    print("Blowfish key must be between 4 and 56 bytes.")
    exit(1)

key = user_key  # Set key

if action == 'encrypt':

    plaintext_input = input("Enter plaintext to encrypt: ")

    plaintext = plaintext_input.encode()

    # Create the Blowfish cipher (CBC mode)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)

    # PKCS padding
    plen = bs - len(plaintext) % bs
    padding = bytes([plen] * plen)

    # Encrypt
    msg = cipher.iv + cipher.encrypt(plaintext + padding)

    print("\nEncrypted (raw bytes):", msg)
    print("Encrypted (hex):", msg.hex())

elif action == 'decrypt':

    ciphertext_input = input("Enter hex string to decrypt: ")

    try:
        ciphertext = binascii.unhexlify(ciphertext_input)
    except binascii.Error:
        print("Invalid hex input.")
        exit(1)

    if len(ciphertext) < bs:
        print("Invalid ciphertext length.")
        exit(1)

    # Extract IV
    iv = ciphertext[:bs]
    cipher_data = ciphertext[bs:]

    # Decrypt setup
    decipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

    decrypted_msg = decipher.decrypt(cipher_data)

    # Remove PKCS padding
    padding_length = decrypted_msg[-1]
    decrypted_msg = decrypted_msg[:-padding_length]

    print("Decrypted message:", decrypted_msg.decode('utf-8'))

else:
    print("Invalid action. Choose 'encrypt' or 'decrypt'.")
