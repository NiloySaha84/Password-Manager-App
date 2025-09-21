import json
import os
import hashlib
import base64
import secrets
import string
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re

KEY_FILE = "key.key"
DATA_FILE = "passwords.json"
CONFIG_FILE = "config.json"


class PasswordManager:
    """Enhanced password manager with zero-knowledge architecture"""

    def __init__(self, master_password: str):
        """Initialize with master password for zero-knowledge encryption"""
        self.master_password = master_password
        self.cipher = self._get_or_create_cipher()
        self._ensure_backward_compatibility()

    def _get_or_create_cipher(self) -> Fernet:
        """Create cipher from master password or legacy key file"""
        if os.path.exists(KEY_FILE) and not os.path.exists(CONFIG_FILE):
            with open(KEY_FILE, "rb") as key_file:
                key = key_file.read()
            return Fernet(key)

        salt = self._get_or_create_salt()
        key = self._derive_key(self.master_password, salt)
        return Fernet(key)

    def _get_or_create_salt(self) -> bytes:
        """Get or create salt for key derivation"""
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                return base64.b64decode(config["salt"])
        except (FileNotFoundError, KeyError):
            salt = os.urandom(16)
            config = {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "version": "2.0",
                "created_at": datetime.now().isoformat()
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f)
            return salt

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _ensure_backward_compatibility(self):
        """Ensure backward compatibility with existing data"""
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r") as f:
                    data = json.load(f)

                needs_migration = False
                for site, creds in data.items():
                    if not isinstance(creds, dict) or 'username' not in creds:
                        continue
                    if 'category' not in creds or 'created_at' not in creds:
                        needs_migration = True
                        break

                if needs_migration:
                    self._migrate_data(data)
            except (json.JSONDecodeError, Exception):
                pass

    def _migrate_data(self, data: Dict[str, Any]):
        """Migrate old data format to new format"""
        migrated_data = {}
        for site, creds in data.items():
            if isinstance(creds, dict) and 'username' in creds:
                migrated_data[site] = {
                    'username': creds['username'],
                    'password': creds['password'],
                    'category': creds.get('category', 'Other'),
                    'notes': creds.get('notes', ''),
                    'created_at': creds.get('created_at', datetime.now().isoformat()),
                    'updated_at': creds.get('updated_at', datetime.now().isoformat())
                }

        with open(DATA_FILE, "w") as f:
            json.dump(migrated_data, f, indent=4)

    def save_password(self, website: str, username: str, password: str,
                      category: str = "Other", notes: str = "") -> bool:
        """Save a password with additional metadata"""
        try:
            encrypted_password = self.cipher.encrypt(password.encode()).decode('utf-8')

            try:
                with open(DATA_FILE, "r") as file:
                    data = json.load(file)
            except (FileNotFoundError, json.JSONDecodeError):
                data = {}

            data[website] = {
                "username": username,
                "password": encrypted_password,
                "category": category,
                "notes": notes,
                "created_at": data.get(website, {}).get('created_at', datetime.now().isoformat()),
                "updated_at": datetime.now().isoformat()
            }

            with open(DATA_FILE, "w") as file:
                json.dump(data, file, indent=4)

            return True
        except Exception as e:
            print(f"Error saving password: {e}")
            return False

    def get_all_passwords(self) -> Dict[str, Dict[str, str]]:
        """Get all passwords (fixed the bug in original code)"""
        try:
            with open(DATA_FILE, "r") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

        decrypted_data = {}
        for site, creds in data.items():
            try:
                decrypted_password = self.cipher.decrypt(creds['password'].encode()).decode()
                decrypted_data[site] = {
                    "username": creds["username"],
                    "password": decrypted_password,
                    "category": creds.get("category", "Other"),
                    "notes": creds.get("notes", ""),
                    "created_at": creds.get("created_at", ""),
                    "updated_at": creds.get("updated_at", "")
                }
            except Exception as e:
                print(f"Error decrypting password for {site}: {e}")
                continue

        return decrypted_data

    def search_passwords(self, search_term: str) -> Dict[str, Dict[str, str]]:
        """Enhanced search across website, username, category, and notes"""
        passwords = self.get_all_passwords()
        results = {}

        search_lower = search_term.lower()
        for site, creds in passwords.items():
            if (search_lower in site.lower() or
                    search_lower in creds['username'].lower() or
                    search_lower in creds.get('category', '').lower() or
                    search_lower in creds.get('notes', '').lower()):
                results[site] = creds

        return results

    def delete(self, website: str) -> bool:
        """Delete a password entry"""
        try:
            with open(DATA_FILE, "r") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return False

        if website in data:
            del data[website]
            with open(DATA_FILE, "w") as file:
                json.dump(data, file, indent=4)
            return True
        return False


def generate_strong_password(length: int = 16,
                             include_upper: bool = True,
                             include_lower: bool = True,
                             include_digits: bool = True,
                             include_symbols: bool = True,
                             exclude_ambiguous: bool = False) -> str:
    """Generate a strong random password with customizable options"""
    characters = ""

    if include_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('O', '').replace('I', '')
        characters += chars

    if include_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('l', '').replace('o', '')
        characters += chars

    if include_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
        characters += chars

    if include_symbols:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not characters:
        characters = string.ascii_letters + string.digits

    password = []
    if include_upper:
        upper_chars = string.ascii_uppercase
        if exclude_ambiguous:
            upper_chars = upper_chars.replace('O', '').replace('I', '')
        if upper_chars:
            password.append(secrets.choice(upper_chars))

    if include_lower:
        lower_chars = string.ascii_lowercase
        if exclude_ambiguous:
            lower_chars = lower_chars.replace('l', '').replace('o', '')
        if lower_chars:
            password.append(secrets.choice(lower_chars))

    if include_digits:
        digit_chars = string.digits
        if exclude_ambiguous:
            digit_chars = digit_chars.replace('0', '').replace('1', '')
        if digit_chars:
            password.append(secrets.choice(digit_chars))

    if include_symbols:
        password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    for _ in range(length - len(password)):
        password.append(secrets.choice(characters))

    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def check_password_strength(password: str) -> int:
    """Check password strength (1=weak, 2=medium, 3=strong)"""
    score = 0

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1

    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[0-9]', password):
        score += 1
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        score += 1

    if not re.search(r'(.)\1{2,}', password):
        score += 1
    if not re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
        score += 1

    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome']
    if password.lower() not in common_passwords:
        score += 1

    if score >= 7:
        return 3
    elif score >= 4:
        return 2
    else:
        return 1


def analyze_password_health(passwords: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    """Analyze overall password health and security metrics"""
    total = len(passwords)
    if total == 0:
        return {
            'total': 0, 'strong': 0, 'medium': 0, 'weak': 0,
            'strong_percentage': 0, 'medium_percentage': 0, 'weak_percentage': 0,
            'duplicates': 0, 'duplicate_sites': {}, 'weak_sites': [],
            'old_sites': []
        }

    strong, medium, weak = 0, 0, 0
    weak_sites = []
    password_hashes = {}
    old_sites = []

    for site, creds in passwords.items():
        strength = check_password_strength(creds['password'])
        if strength == 3:
            strong += 1
        elif strength == 2:
            medium += 1
        else:
            weak += 1
            weak_sites.append(site)

        pwd_hash = hashlib.sha256(creds['password'].encode()).hexdigest()
        if pwd_hash not in password_hashes:
            password_hashes[pwd_hash] = []
        password_hashes[pwd_hash].append(site)

        if creds.get('created_at'):
            try:
                created = datetime.fromisoformat(creds['created_at'])
                if (datetime.now() - created).days > 90:
                    old_sites.append(site)
            except:
                pass

    duplicate_sites = {k: v for k, v in password_hashes.items() if len(v) > 1}
    duplicate_count = sum(len(sites) - 1 for sites in duplicate_sites.values())

    return {
        'total': total,
        'strong': strong,
        'medium': medium,
        'weak': weak,
        'strong_percentage': (strong / total) * 100,
        'medium_percentage': (medium / total) * 100,
        'weak_percentage': (weak / total) * 100,
        'duplicates': duplicate_count,
        'duplicate_sites': duplicate_sites,
        'weak_sites': weak_sites,
        'old_sites': old_sites
    }


def export_passwords(pm: PasswordManager, format: str = "json") -> str:
    """Export passwords in specified format"""
    try:
        passwords = pm.get_all_passwords()

        if format.lower() == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Website', 'Username', 'Password', 'Category', 'Notes', 'Created', 'Updated'])

            for site, creds in passwords.items():
                writer.writerow([
                    site,
                    creds['username'],
                    creds['password'],
                    creds.get('category', 'Other'),
                    creds.get('notes', ''),
                    creds.get('created_at', ''),
                    creds.get('updated_at', '')
                ])

            return output.getvalue()
        else:
            export_data = {
                'version': '2.0',
                'exported_at': datetime.now().isoformat(),
                'passwords': passwords
            }
            return json.dumps(export_data, indent=2)
    except Exception as e:
        print(f"Export error: {e}")
        return ""


def import_passwords(pm: PasswordManager, file_content) -> Tuple[bool, str]:
    """Import passwords from file"""
    try:
        content = file_content.read()

        if file_content.name.endswith('.csv'):
            import csv
            import io

            text = content.decode('utf-8')
            reader = csv.DictReader(io.StringIO(text))

            imported = 0
            for row in reader:
                site = row.get('Website', row.get('website', ''))
                username = row.get('Username', row.get('username', ''))
                password = row.get('Password', row.get('password', ''))

                if site and username and password:
                    category = row.get('Category', row.get('category', 'Other'))
                    notes = row.get('Notes', row.get('notes', ''))

                    pm.save_password(site, username, password, category, notes)
                    imported += 1

            return True, f"Successfully imported {imported} passwords!"

        else:
            data = json.loads(content)

            if 'passwords' in data:
                passwords = data['passwords']
            else:
                passwords = data

            imported = 0
            for site, creds in passwords.items():
                if isinstance(creds, dict) and 'username' in creds and 'password' in creds:
                    pm.save_password(
                        site,
                        creds['username'],
                        creds['password'],
                        creds.get('category', 'Other'),
                        creds.get('notes', '')
                    )
                    imported += 1

            return True, f"Successfully imported {imported} passwords!"

    except Exception as e:
        return False, f"Import failed: {str(e)}"


def generate_key():
    """Legacy function for backward compatibility"""
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key


if os.path.exists(KEY_FILE) and not os.path.exists(CONFIG_FILE):
    key = generate_key()
    cipher = Fernet(key)
else:
    key = None
    cipher = None


def save_password(website: str, username: str, password: str) -> bool:
    """Legacy save function for backward compatibility"""
    global cipher
    if cipher is None:
        pm = PasswordManager("legacy_mode")
        return pm.save_password(website, username, password)

    encrypted_password = cipher.encrypt(password.encode()).decode('utf-8')
    try:
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    data[website] = {"username": username, "password": encrypted_password}
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)
    return True


def get_all_passwords() -> Dict[str, Dict[str, str]]:
    """Legacy get all passwords function for backward compatibility"""
    global cipher
    if cipher is None:
        pm = PasswordManager("legacy_mode")
        return pm.get_all_passwords()

    try:
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

    decrypted_data = {}
    for site, creds in data.items():
        try:
            decrypted_password = cipher.decrypt(creds['password'].encode()).decode()
            decrypted_data[site] = {
                "username": creds["username"],
                "password": decrypted_password
            }
        except Exception:
            continue
    return decrypted_data


def search_password(website: str) -> Optional[Dict[str, str]]:
    """Legacy search function for backward compatibility"""
    passwords = get_all_passwords()
    return passwords.get(website, None)


def delete(website: str) -> bool:
    """Legacy delete function for backward compatibility"""
    global cipher
    if cipher is None:
        pm = PasswordManager("legacy_mode")
        return pm.delete(website)

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
    return False