<img width="2068" height="1319" alt="image" src="https://github.com/user-attachments/assets/f21c78a9-772b-4e7e-8ad6-93c62d505f91" />🔐 Multilayer Encryption System

(Educational Cryptography Project)

📌 Overview

This project implements a multilayer encryption and decryption system to demonstrate defense-in-depth cryptographic design.
It combines modern authenticated encryption with classic symmetric ciphers, secure key derivation, and session-based key wrapping, all accessible through a CLI-based interface.

⚠️ Academic Disclaimer
This system is developed strictly for educational purposes and is not intended for real-world production use.

🎯 Project Objectives

Demonstrate layered cryptographic security

Compare modern vs legacy encryption algorithms

Implement secure key derivation and wrapping

Practice code organization, documentation, and defense

Meet all individual project assessment requirements

📊 System Architecture Diagram
┌───────────────────────────────────────────────────────────┐
│                  Multi-Layer Encryption Suite              │
└───────────────────────────────────────────────────────────┘

                 ┌───────────────────────┐
                 │  Rich UI (main.py)    │
                 │  - Menu System        │
                 │  - System Info        │
                 │  - WiFi Scanner       │
                 │  - Logs Panel         │
                 └───────────────▲───────┘
                                 │ Calls
                 ┌───────────────┴───────────────┐
                 │       Encryption Engine        │
                 │        (triple_enc.py)         │
                 └───────────────┬───────────────┘
                                 │
                    ┌────────────┼─────────────┐
                    │            │             │
                    ▼            ▼             ▼
        ┌────────────────┐  ┌──────────────┐  ┌────────────────┐
        │ ChaCha20 Layer │  │ AES-256-CBC  │  │ Blowfish-CBC   │
        └────────────────┘  └──────────────┘  └────────────────┘
                    │            │             │
                    └────────────┴─────────────┘
                                 ▼
                       ┌──────────────────┐
                       │   RC4 Layer      │
                       │ (AdvancedRC4)    │
                       └──────────────────┘
                                 │
                                 ▼
                      ┌─────────────────────┐
                      │  Saved Session Data │
                      │   (all_session/)    │
                      └─────────────────────┘

🔐 Encryption Flow Diagram
PLAINTEXT
   │
   ▼
┌────────────────────┐
│  ChaCha20-Poly1305 │
└────────────────────┘
   │
   ▼
┌────────────────────┐
│    AES-256-CBC     │
└────────────────────┘
   │
   ▼
┌────────────────────┐
│    Blowfish-CBC    │
└────────────────────┘
   │
   ▼
┌────────────────────┐
│        RC4          │
└────────────────────┘
   │
   ▼
 FINAL HEX CIPHERTEXT

🔓 Decryption Flow Diagram
CIPHERTEXT
   │
   ▼
┌────────────────────┐
│        RC4          │
└────────────────────┘
   │
   ▼
┌────────────────────┐
│    Blowfish-CBC    │
└────────────────────┘
   │
   ▼
┌────────────────────┐
│    AES-256-CBC     │
└────────────────────┘
   │
   ▼
┌────────────────────┐
│  ChaCha20-Poly1305 │
└────────────────────┘
   │
   ▼
PLAINTEXT


Algorithm	                Role
ChaCha20-Poly1305	        Authenticated encryption & integrity
AES-256-CBC	                Strong symmetric encryption
Blowfish-CBC	                Legacy block cipher (educational)
RC4 (Custom)	                Outer obfuscation layer
PBKDF2	                        Password-based key derivation
AES-GCM	                        Secure key wrapping

🗂️ Project Structure
Source_Code/
│
├── all_session/
│   ├── ciphertext.hex           # Final encrypted output
│   └── session_wrapped.json     # Wrapped session keys
│
├── FinalCode/
│   ├── __pycache__/
│   ├── main.py                  # CLI entry point (Rich-based UI)
│   ├── triple_enc.py            # Core multilayer encryption logic
│   ├── rc4_addingx.py            # Advanced RC4 implementation
│   └── requirements.txt         # Python dependencies
│
├── step_by_step_code/
│   ├── __pycache__/
│   ├── adding_x.py               # Helper utilities
│   ├── aes_256_mode_cbc.py       # AES-256-CBC implementation
│   ├── aes_session.json          # AES session data
│   ├── blowfish.py               # Blowfish cipher
│   ├── blowfish_key.bin          # Blowfish key storage
│   ├── chacha_key.bin            # ChaCha20 key storage
│   ├── chacha_output.json        # AEAD output
│   ├── chacha_poly1305.py        # ChaCha20-Poly1305 logic
│   └── ciphertext.hex            # Intermediate ciphertext
│
├── venv/                         # Python virtual environment
├── .gitignore
├── pyvenv.cfg
└── README.md


🖥️ Key Features

- Rich-based menu-driven CLI
- Multilayer encryption & decryption
- Secure password-based key derivation
- Session key wrapping with AES-GCM
- Authenticated encryption with tamper detection
- Step-by-step implementation for learning & explanation
- Designed for code defense and viva/Q&A

⚙️ Installation
1. Clone the repository
git clone https://github.com/panhapanha-kskt/Final_project_crypto.git
cd Final_project_crypto

⚙️ Requirements

- Python 3.9 or newer
- OS: Linux / Windows / macOS

Python Dependencies
Listed in FinalCode/requirements.txt
Install using:
        pip install -r FinalCode/requirements.txt

🚀 How to Run
1️⃣ Activate Virtual Environment (optional but recommended)
        source venv/bin/activate   # Linux/macOS
        venv\Scripts\activate      # Windows
        
2️⃣ Run the Main Application
        cd Source_Code/FinalCode
        python3 main.py
        
3️⃣ Available Options
<img width="2068" height="1319" alt="Screenshot 2025-12-20 001824" src="https://github.com/user-attachments/assets/65912b7f-3d9c-45c8-ab2f-e19bd116b9eb" />

🔎Security Notes
- RC4 is used only for academic comparison
- Keys are derived using PBKDF2
- ChaCha20-Poly1305 ensures integrity & authenticity
- AES-GCM protects wrapped session keys
- Demonstrates layered security, not minimal cipher design
