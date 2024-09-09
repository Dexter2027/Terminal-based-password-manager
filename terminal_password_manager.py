
import json
import os
import getpass
import hashlib
import base64
import secrets
from cryptography.fernet import Fernet  # type: ignore


PASSWORD_FILE = 'passwords.json'
MASTER_PASSWORD_HASH = 'master_password_hash.txt'

def load_key():
    if os.path.exists('key.key'):
        with open('key.key', 'rb') as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open('key.key', 'wb') as key_file:
            key_file.write(key)
        return key

def encrypt_password(plain_text_password, key):
    f = Fernet(key)
    return f.encrypt(plain_text_password.encode()).decode()

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

def hash_master_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate():
    if os.path.exists(MASTER_PASSWORD_HASH):
        with open(MASTER_PASSWORD_HASH, 'r') as f:
            stored_hash = f.read()
    else:
        print("Set up a master password for the first time.")
        master_password = getpass.getpass("Enter new master password: ")
        with open(MASTER_PASSWORD_HASH, 'w') as f:
            f.write(hash_master_password(master_password))
        return True
    
    master_password = getpass.getpass("Enter master password: ")
    return hash_master_password(master_password) == stored_hash

def load_passwords():
    if not os.path.exists(PASSWORD_FILE):
        return {"accounts": []}
    
    with open(PASSWORD_FILE, 'r') as file:
        return json.load(file)

def save_passwords(data):
    with open(PASSWORD_FILE, 'w') as file:
        json.dump(data, file, indent=4)

def add_password():
    account_name = input("Enter account name: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    key = load_key()
    encrypted_password = encrypt_password(password, key)
    
    passwords = load_passwords()
    passwords["accounts"].append({
        "account_name": account_name,
        "username": username,
        "encrypted_password": encrypted_password
    })
    
    save_passwords(passwords)
    print("Password added successfully!")

def view_passwords():
    if authenticate():
        passwords = load_passwords()
        for account in passwords["accounts"]:
            print(f"Account: {account['account_name']}, Username: {account['username']}")
        
        if input("Do you want to reveal a password? (y/n): ").lower() == 'y':
            account_name = input("Enter the account name to reveal the password: ")
            account = next((a for a in passwords["accounts"] if a["account_name"] == account_name), None)
            if account:
                key = load_key()
                print(f"Password for {account_name}: {decrypt_password(account['encrypted_password'], key)}")
            else:
                print("Account not found.")
    else:
        print("Authentication failed!")

def delete_password():
    if authenticate():
        account_name = input("Enter the account name to delete: ")
        passwords = load_passwords()
        passwords["accounts"] = [a for a in passwords["accounts"] if a["account_name"] != account_name]
        save_passwords(passwords)
        print("Password deleted successfully!")
    else:
        print("Authentication failed!")


def update_password():
    if authenticate():
        account_name = input("Enter the account name to update: ")
        new_password = getpass.getpass("Enter the new password: ")
        
        passwords = load_passwords()
        account = next((a for a in passwords["accounts"] if a["account_name"] == account_name), None)
        
        if account:
            key = load_key()
            account['encrypted_password'] = encrypt_password(new_password, key)
            save_passwords(passwords)
            print("Password updated successfully!")
        else:
            print("Account not found.")
    else:
        print("Authentication failed!")

def generate_password(length=16):
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    password = ''.join(secrets.choice(characters) for _ in range(length))
    print(f"Generated password: {password}")

def main():
    while True:
        print("\nPassword Manager")
        print("1. Add Password")
        print("2. View Saved Passwords")
        print("3. Delete a Password")
        print("4. Update a Password")
        print("5. Generate Strong Password")
        print("6. Exit")
        
        choice = input("Select an option: ")
        
        if choice == '1':
            add_password()
        elif choice == '2':
            view_passwords()
        elif choice == '3':
            delete_password()
        elif choice == '4':
            update_password()
        elif choice == '5':
            length = int(input("Enter the password length (default 16): ") or 16)
            generate_password(length)
        elif choice == '6':
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main()
