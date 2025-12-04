import os
from triple_enc import multilayer_encrypt_flow, multilayer_decrypt_flow
from rc4_addingx import AdvancedRC4, bytes_to_c_format


def clear_screen():
    """Clear console screen."""
    os.system("cls" if os.name == "nt" else "clear")


def main():
    """Main menu loop."""
    while True:
        clear_screen()
        print("=== Cryptography Project Main Menu ===\n")
        print("1. Multilayer Encryption (ChaCha20 → AES → Blowfish → RC4)")
        print("2. Multilayer Decryption (RC4 → Blowfish → AES → ChaCha20)")
        print("3. Exit")

        choice = input("\nSelect an option (1-3): ").strip()

        if choice == "1":
            multilayer_encrypt_flow()
        elif choice == "2":
            multilayer_decrypt_flow()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
