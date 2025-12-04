I. Introduction
1. Overview of project goal
     Cryptography is the process of converting a normal plaintext to unreadable text in the form of using different algorithms. It can be used for authentication, protecting data from criminal which stands against them by locking the particular data using the key. Cryptography involves: Plaintext, Encryption Algorithm, Ciphertext, Decryption Algorithm, Encryption key and Decryption key. The stronger the cryptographic design, the harder it becomes for attackers to compromise the protected information.
     This project aims to design and implement a Cascade Multi-Layer Encryption Tool, where a single plaintext message is encrypted through four different cryptographic algorithms applied sequentially: ChaCha20-Poly1305, AES-256 in CBC mode, Blowfish in CBC mode, and the classic RC4 stream cipher. Each algorithm adds a new protective layer, similar to an “onion model,” where every layer wraps the previous one. This multi-layer approach increases resistance against brute-force attacks, key recovery attempts, and cryptanalytic techniques, especially when different cipher families are combined.
   
2. Problem / Solution
     This project addresses several important problems in modern cryptography:
• Single-algorithm dependency
• Vulnerabilities when one cipher becomes weak
• Key reuse and predictability issues
• Risk of brute-force or cryptanalysis
• Lack of layered security in simple encryption tools
     To solve these issues, the system encrypts data using fount independent keys and four separate cryptographic algorithms. This ensures that even if one layer is compromised, the remaining layers still protect the data. The project also includes support for encoding formats such as Base64 and hexadecimal, allowing ciphertext to be safely transmitted or stored in textual form.
3. Motivation
     The motivation for this project is to explore how modern and legacy cryptographic algorithms behave when integrated into one system. Studying these algorithms together helps build a deeper understanding of block ciphers, stream ciphers, authenticated encryption and secure key management.
4. Related Cryptographic Concepts
     This project involves several important cryptographic concepts that are directly reflected in the implementation of the four-layer encryption system:
• Symmetric-Key Encryption
This encryption uses a single shared secret key for both encrypting and decrypting data. This method is known for being fast and efficient, making it ideal for securing large amounts of data.
• Block Ciphers
This tool uses two block ciphers such as AES-256 in CBC mode, Blowfish in CBC mode.
• Stream Ciphers
This cipher is a symmetric encryption method that encrypts data one bit or byte at a time by combining it with a pseudorandom keystream. The keystream generation is used by a pseudorandom number generator (PRNG) to create a long, pseudo-random sequence of bits.
• Key Scheduling Algorithm
This is a process used in symmetric encryption to generate a series of unique subkeys (or round keys) from a single original key.
• Nonces
o Chacha-Poly1350 requires a unique nonce for every encryption
o Prevents keystream reuse.
• Initialization Vectors (IVs) This is a random or pseudorandom value used in cryptography to ensure that identical plaintexts encrypt to different ciphertexts, thereby increasing security. In my concepts require a random IVs to ensure ciphertext uniqueness.
• Padding Schemes
o Block ciphers need PKCS7 padding when plaintext is not a full block.
• Encoding Formats
o Base64 and Hex encoding are used to represent binary ciphertext in printable string form.
o Ensures safe storage and transmission over JSON, text files, or networks.
• Multi-Key Management
o This tool uses four separate keys, one for each algorithm.
o Prevents a single key compromise from fully exposing the data.
• Hybrid Cryptographic Design
o Combines legacy ciphers (RC4, Blowfish) and modern ciphers (AES-256, ChaCha-Poly1350).
o Demonstrates practical differences between cipher families and security models.
