import json
from cryptography.fernet import Fernet

KEY_FILE = "key.key"
DATA_FILE = "passwords.json"

def generate_key():
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

key = generate_key()
cipher = Fernet(key)

def save_password(website, username, password):
    encrypted_password = cipher.encrypt(password.encode()).decode('utf-8')
    try:
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    data[website] = {"username": username, "password": encrypted_password}
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

def get_all_passwords():
    try:
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    decrypted_data = {}
    for site, creds in data.items():
        decrypted_passwords = cipher.decrypt(creds['password'].encode()).decode()
        decrypted_data[site] = {
            "username": creds["username"],
            "password": decrypted_passwords
        }
        return decrypted_data

def search_password(website):
    passwords = get_all_passwords()
    return passwords.get(website, None)

def delete(website):
    try:
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    if website in data:
        del data[website]

        with open(DATA_FILE, "w") as file:
            json.dump(data, file, indent=4)
        return True
    else:
        return False



