def add_x_to_bytes(hex_string):
    hex_string = hex_string.replace(" ", "").replace("\n", "")

    # Ensure even length
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string length must be even!")

    # Add \x every 2 characters
    return "".join(f"\\x{hex_string[i:i+2]}" for i in range(0, len(hex_string), 2))


# ================================
# Ask user to input the hex bytes
# ================================
hex_string = input("Enter your hex string: ").strip()

try:
    formatted = add_x_to_bytes(hex_string)
    print("\nFormatted bytes:")
    print(formatted)
except Exception as e:
    print(f"Error: {e}")
