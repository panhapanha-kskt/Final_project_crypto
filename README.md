🔐 Multi-Layer Encryption Suite
Final Individual Project – Cryptography

A comprehensive cryptographic demonstration tool featuring a four-layer encryption pipeline, a rich terminal UI, live system/WiFi diagnostics, and a standalone RC4 text encryption utility.

Designed for education, research, and conceptual understanding of layered cryptography.

📘 Purpose of This Tool

This project was developed to help students, researchers, and developers understand:

How different cryptographic algorithms behave in a layered environment

How secure communication concepts are modeled in academic settings

How keys, sessions, and intermediate states are managed

How encryption pipelines are implemented in practice

This tool simulates concepts used in sectors such as secure communication research, defense communication studies, and critical data protection — but is not intended for real-world military or production security.

⚠️ Educational Use Only

This project is intended strictly for:

Learning

Laboratory testing

Simulation

Academic demonstrations

It must not be used to secure real operational, confidential, or military communications.

🚀 Features
🔹 1. Multi-Layer Encryption Pipeline

The encryption engine applies the following layers sequentially:

ChaCha20-Poly1305

AES-256-CBC

Blowfish-CBC

Advanced RC4 (custom implementation)

Decryption reverses these steps automatically.

🔹 2. Rich Terminal UI (RICH Library)

The UI includes:

Live WiFi and network information

System diagnostics (hostname, IPv4, interface)

Multi-panel layout

Interactive menu

Real-time logs

Encryption/decryption controls

🔹 3. Standalone RC4 CLI Utility

Supports:

Text mode

Hex mode

Python bytes literal (b"\x41\x42...")

Output in: raw, hex, base64, C array (\x00), Python bytes array

File output support via -o

🔹 4. Session & Key Management

Automatically stores:

AES session files

Blowfish keys

ChaCha20 output

RC4 key

Final ciphertext

All of these files are stored in:

Source_Code/all_session/

📁 Project Structure
D:\YEAR3 TERM1\CRYPTOGRAPHY\FINAL_PROJECT_CRYPTO\SOURCE_CODE
├── all_session
│       aes_session.json
│       blowfish_key.bin
│       chacha_key.bin
│       chacha_output.json
│       ciphertext.hex
│       rc4_key.bin
│
├── FinalCode
│   │   main.py
│   │   rc4_addingx.py
│   │   triple_enc.py
│   │
│   └── __pycache__
│           main.cpython-314.pyc
│           rc4_addingx.cpython-314.pyc
│           triple_enc.cpython-314.pyc
│
└── step_by_step_code_combination
        adding_x.py
        aes_256_mode_cbc.py
        aes_session.json
        blowfish.py
        blowfish_key.bin
        chacha_key.bin
        chacha_output.json
        chacha_poly1305.py
        ciphertext.hex

⚙️ Installation
1. Clone the repository
git clone https://github.com/panhapanha-kskt/Final_project_crypto.git
cd Final_project_crypto

2. Create virtual environment
python3 -m venv venv

3. Activate virtual environment

Windows:

venv\Scripts\activate


Linux/macOS:

source venv/bin/activate

4. Install dependencies
cd Source_Code/FinalCode
pip install -r requirements.txt

▶️ Running the Main Program (Rich UI)
python3 Source_Code/FinalCode/main.py


You will see:

System info

WiFi info

Encryption menu

Logs panel

🧨 Using the Multi-Layer Encryption Tool
1. Encrypt

Select:

[1] Multilayer Encryption (ChaCha20 → AES → Blowfish → RC4)


You will be asked:

Enter plaintext:


When done, the tool automatically saves:

Keys

Ciphertext

Intermediate output files

Stored in all_session/.

2. Decrypt

Select:

[2] Multilayer Decryption (RC4 → Blowfish → AES → ChaCha20)


The tool loads data from all_session/ and restores the original plaintext.

💡 RC4 Standalone CLI Usage
Encrypt
python rc4_addingx.py -m encrypt -k "password123" -i "hello"

Decrypt
python rc4_addingx.py -m decrypt -k "password123" -i "5a1f9e..."

Supports:

Raw text

Hex strings

Python bytes (b"\x41\x42\x43")

Saving to file (-o output.bin)

📚 Technical Summary
🔒 Encryption Order (Encrypt Mode)
Plaintext
   ↓
ChaCha20-Poly1305
   ↓
AES-256-CBC
   ↓
Blowfish-CBC
   ↓
Advanced RC4
   ↓
ciphertext.hex

🔓 Decryption Order (Decrypt Mode)
RC4 → Blowfish → AES → ChaCha20

⚠️ Important Notes

✔ Keys and intermediate results are stored automatically
✔ Do NOT delete all_session/ if you want decryption to work
✔ RC4 tool is separate from multilayer pipeline
✔ This project is for education and research only

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

🧩 RC4 Standalone Tool Diagram
INPUT TEXT / HEX / PY BYTES
        │
        ▼
┌───────────────┐
│  KSA (Keying) │
└───────────────┘
        │
        ▼
┌───────────────┐
│ PRGA (Stream) │
└───────────────┘
        │
        ▼
┌───────────────┐
│   XOR Stage   │
└───────────────┘
        │
        ▼
 OUTPUT (hex/raw/base64/etc.)

📂 Session Files Diagram
all_session/
│
├── aes_session.json
├── blowfish_key.bin
├── chacha_key.bin
├── chacha_output.json
├── ciphertext.hex
└── rc4_key.bin
