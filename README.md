Secure File Encryption Tool

A Python-based CLI application for secure encryption and decryption of files. This tool ensures the confidentiality and integrity of your files using AES encryption and SHA256 hashing.

Features

File Encryption: Encrypts any file with a password and saves it securely.  
File Decryption: Decrypts encrypted files if the correct password is provided.  
File Integrity Check: Validates the integrity of the decrypted file using SHA256 hashing.  
File Type Detection: Automatically detects and displays the type of file being processed.

Usage

1. Encrypt a File
Select Option 1 in the menu.
Provide the path of the file to encrypt.
Enter a password for encryption.
The encrypted file will be saved with the .enc extension.
2. Decrypt a File
Select Option 2 in the menu.
Provide the path of the .enc file to decrypt.
Enter the password used during encryption.
If successful, the decrypted file will be saved with its original extension.
3. Exit
Select Option 3 to exit the program.

Security Details

Encryption Algorithm: AES (Advanced Encryption Standard) in CFB mode.  
Key Derivation: PBKDF2HMAC with 100,000 iterations and SHA256.  
Initialization Vector (IV): A unique 16-byte IV is generated for every encryption operation.  
Integrity Check: SHA256 hash ensures the decrypted file has not been tampered with.  

Future Improvements

Add support for asymmetric encryption (e.g., RSA).  
Improve error handling and provide more detailed logs.  
Add a GUI for better user experience.  
Optimize for large files with streaming encryption.
