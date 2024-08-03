from cryptography.fernet import Fernet

def generate_key():
    """Generate a new encryption key."""
    return Fernet.generate_key()

def save_key(key, filename):
    """Save the encryption key to a file."""
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename):
    """Load the encryption key from a file."""
    with open(filename, 'rb') as key_file:
        return key_file.read()

def encrypt_message(message, key):
    """Encrypt the message using the provided key."""
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    """Decrypt the message using the provided key."""
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message
