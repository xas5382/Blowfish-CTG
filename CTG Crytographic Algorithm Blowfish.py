from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
import hashlib

def generate_key(key_size):
    return get_random_bytes(key_size)

def generate_iv():
    return get_random_bytes(Blowfish.block_size)

def pad_data(data):
    block_size = 8
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad_data(data):
    padding = data[-1]
    return data[:-padding]

def encrypt(plaintext, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    padded_plaintext = pad_data(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt(ciphertext, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad_data(padded_plaintext)
    return plaintext

def main():
    while True:
        try:
            key_size = int(input("Enter the key size (in bytes): "))
        except ValueError:
            print("Please enter a positive whole number \n")
            continue
        if key_size < 4 or key_size > 56:
            print("Key length must be between 4 and 56 bytes.\n")
            continue
        elif key_size < 16:
            reply = ""
            print(f"Using a key length of {key_size} bytes could result in your key being easily cracked.")
            while True:
                reply = input(f"Do you wish to continue using a {key_size} bytes key? (y/n): ")
                if reply.lower() == "y":
                    break
                elif reply.lower() == "n":
                    break
                else:
                    print("Please reply with 'y' or 'n' \n")
                    continue
            if reply == "y":
                break
            else:
                print()
                continue
            
        else:
            break
    
    key = generate_key(key_size)
    iv = generate_iv()
    
    while True:
        print("\nMenu:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ")
        print()
        
        if choice == '1':
            plaintext = input("Enter the value to encrypt: ").encode('utf-8')
            encrypted_value = encrypt(plaintext, key, iv)
            print("Encrypted Value (in hex):", encrypted_value.hex())
        elif choice == '2':
            ciphertext_hex = input("Enter the encrypted value in hex format: ")
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
            except ValueError:
                print("Invalid hex value")
                continue
            decrypted_value = decrypt(ciphertext, key, iv)
            print("Decrypted Value (in hex):", decrypted_value.decode('utf-8'))
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
