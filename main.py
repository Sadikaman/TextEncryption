from encryption import generate_key, save_key, encrypt_message, load_key

def main():
    # Generate and save key
    key = generate_key()
    save_key(key, 'encryption_key.key')
    
    # Encrypt a message
    message = input("Enter the message to encrypt: ")
    encrypted_message = encrypt_message(message, key)
    print("Encrypted message:", encrypted_message.decode())
    
    # Decryption example (can be tested separately)
    # decrypted_message = decrypt_message(encrypted_message, key)
    # print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
