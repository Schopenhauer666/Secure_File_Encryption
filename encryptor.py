import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import mimetypes
import hashlib

# Συνάρτηση για δημιουργία κλειδιού
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_file_hash(data):
    return hashlib.sha256(data).digest()
	
def get_file_type(file_path):
	file_type, _=mimetypes.guess_type(file_path)
	return file_type if file_type else "Unknown"

# Συνάρτηση για κρυπτογράφηση αρχείου
def encrypt_file(file_path, password):
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return
	
    file_type = get_file_type(file_path)
    print(f"[INFO] File type detected: {file_type}")

    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()
	
    file_hash = generate_file_hash(plaintext)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file = file_path + '.enc'
    with open(encrypted_file, 'wb') as f:
        f.write(salt + iv + file_hash + ciphertext)

    print(f"File '{file_path}' encrypted successfully! Saved as '{encrypted_file}'.")

# Συνάρτηση για αποκρυπτογράφηση αρχείου
def decrypt_file(file_path, password):
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' does not exist.")
        return
    
    file_type = get_file_type(file_path)
    print(f"[INFO] File type detected: {file_type}")


    with open(file_path, 'rb') as f:
        data = f.read()

    salt, iv, ciphertext = data[:16], data[16:32], data[64:]
    file_hash=data[32:64]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        print("Error: Decryption failed. Incorrect password or corrupted file.")
        return
	
    if generate_file_hash(plaintext) != file_hash:
        print("Error: File integrity check failed. The file may have been tampered with.")		
        return

    original_file = file_path.replace('.enc', '')
    with open(original_file, 'wb') as f:
        f.write(plaintext)

    print(f"File '{file_path}' decrypted successfully! Saved as '{original_file}'.")

# Διεπαφή CLI
def main():
    print("Welcome to the Secure File Encryption Tool!")
    print("===========================================")
    print("Options:")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Exit")

    while True:
        choice = input("\nEnter your choice (1/2/3): ").strip()

        if choice == '1':
            file_path = input("Enter the path of the file to encrypt: ").strip()
            password = input("Enter a password for encryption: ").strip()
            encrypt_file(file_path, password)

        elif choice == '2':
            file_path = input("Enter the path of the file to decrypt: ").strip()
            password = input("Enter the password for decryption: ").strip()
            decrypt_file(file_path, password)

        elif choice == '3':
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
