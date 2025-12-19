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
<img width="888" height="1033" alt="image" src="https://github.com/user-attachments/assets/a89a46df-54e1-4767-979c-a9bc195c6016" />


🔐 Encryption Flow Diagram

<img width="883" height="346" alt="image" src="https://github.com/user-attachments/assets/f4444533-80d5-465e-ba1e-c04a56dfa7d6" />


🔓 Decryption Flow Diagram

<img width="893" height="337" alt="image" src="https://github.com/user-attachments/assets/cf38f86d-e3a5-41a1-bcac-162ab75d0771" />


🔐 Cryptographic Algorithms Used


<img width="874" height="375" alt="image" src="https://github.com/user-attachments/assets/960135cb-2da3-4a9d-b282-757f21d9f262" />



🗂️ Project Structure

<img width="889" height="849" alt="image" src="https://github.com/user-attachments/assets/41cffcb6-c91d-46c5-a2f4-1ff2bb0c0fb5" />


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
