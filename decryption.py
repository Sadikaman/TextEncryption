from encryption import load_key, decrypt_message

def main():
    key = load_key('encryption_key.key')
    encrypted_message = input("Enter the encrypted message: ").encode()
    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
