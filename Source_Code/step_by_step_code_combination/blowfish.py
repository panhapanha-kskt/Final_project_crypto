from Crypto.Cipher import Blowfish
import binascii  # To convert hex to bytes

# Blowfish block size
bs = Blowfish.block_size

# Default key (change as needed)
key = b'MyDefaultKey123'  # Example default key (must be bytes)

# --- USER INPUT ---
action = input("Choose action (encrypt/decrypt): ").strip().lower()

if action == 'encrypt':
    plaintext_input = input("Enter plaintext to encrypt: ")

    # Encode the plaintext to bytes
    plaintext = plaintext_input.encode()

    # Create the Blowfish cipher with CBC mode
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)

    # Calculate padding
    plen = bs - len(plaintext) % bs
    padding = bytes([plen] * plen)

    # Encrypt the message
    msg = cipher.iv + cipher.encrypt(plaintext + padding)

    print("\nEncrypted (raw bytes):", msg)
    print("Encrypted (hex):", msg.hex())

elif action == 'decrypt':
    ciphertext_input = input("Enter hex string to decrypt: ")

    try:
        # Convert the hex string to bytes
        ciphertext = binascii.unhexlify(ciphertext_input)
    except binascii.Error:
        print("Invalid hex input.")
        exit(1)

    # Ensure the ciphertext is long enough for a valid IV + data
    if len(ciphertext) < bs:
        print("Invalid ciphertext length.")
        exit(1)

    # Extract the IV and ciphertext
    iv = ciphertext[:bs]
    cipher_data = ciphertext[bs:]

    # Create the Blowfish cipher for decryption with the same key and IV
    decipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

    # Decrypt the ciphertext
    decrypted_msg = decipher.decrypt(cipher_data)

    # Remove padding
    padding_length = decrypted_msg[-1]
    decrypted_msg = decrypted_msg[:-padding_length]

    print("Decrypted message:", decrypted_msg.decode('utf-8'))

else:
    print("Invalid action. Choose 'encrypt' or 'decrypt'.")
