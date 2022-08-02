import base64
import getpass
from os import listdir, mkdir, path
import secrets

import click
from cryptography import fernet
from cryptography.hazmat.primitives.kdf import scrypt

SALT_PATH = "/.psst/salt"
VAULT_PATH = "/.psst/vault"

@click.group()
def cli_group():
    pass


@cli_group.command()
def ls():
    for secret in listdir(VAULT_PATH):
        print(f"  {secret}")


@cli_group.command()
@click.option("-s", "--secret", help="The name of secret to write to.")
@click.option("-v", "--value", help="The value to lock up.")
def register(secret: str, value: str):
    password = getpass.getpass()
    key = key_from_password(password=password, create_salt=True)
    encrypted_value = encrypt_value(key, bytes(value, "utf-8"))
    store_encrypted_secret(secret, encrypted_value)
    exit(0)


@cli_group.command()
@click.option("-s", "--secret", help="The name of secret to look up.")
def ask(secret: str):
    password = getpass.getpass()

    try:
        key = key_from_password(password=password, create_salt=False)
        encrypted_value = load_encrypted_secret(secret)
        print(decrypt_value(key, encrypted_value).decode("utf-8"))
        exit(0)
    except InvalidKeyError as e:
        print("Incorrect Password")
    except NoSaltError as e:
        print("Psst is missing salt. This is bad, it means something is likely misconfigured. Attempt to recover the salt to access secrets.")
    except SecretNotFound as e:
        print("The secret specified was not found.")
    finally:
        exit(1)


"""
Encryption/Decryption
"""
def encrypt_value(key: bytes, value: bytes) -> bytes:
    return fernet.Fernet(key).encrypt(value)


def decrypt_value(key: bytes, value: bytes) -> bytes:
    try:
        return fernet.Fernet(key).decrypt(value)
    except fernet.InvalidToken:
        raise InvalidKeyError()


"""
File operations
"""
def store_encrypted_secret(secret: str, encrypted_value: bytes):
    if not path.exists(VAULT_PATH):
        mkdir(VAULT_PATH)

    with open(f"{VAULT_PATH}/{secret}", "wb") as f:
        f.write(encrypted_value)


def load_encrypted_secret(secret: str) -> bytes:
    if not path.exists(f"{VAULT_PATH}/{secret}"):
        raise SecretNotFound()

    with open(f"{VAULT_PATH}/{secret}", "rb") as f:
        return f.read()


"""
Key/Salt generation
"""
def key_from_password(password: str, create_salt: bool) -> str:
    salt = get_salt(gen_if_none=create_salt)
    return generate_key(password=password, salt=salt)


def generate_key(password: str, salt: bytes) -> str:
    kdf = scrypt.Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key_bytes = kdf.derive(password.encode())

    return base64.urlsafe_b64encode(key_bytes)


def get_salt(gen_if_none: bool) -> bytes:
    if path.exists(SALT_PATH):
        with open(SALT_PATH, "rb") as f:
            return f.read()

    if gen_if_none:
        salt = secrets.token_bytes(16)
        with open(SALT_PATH, "wb") as f:
            f.write(salt)

        return salt

    raise NoSaltError("No salt found")


class InvalidKeyError(Exception):
    pass

class NoSaltError(Exception):
    pass

class SecretNotFound(Exception):
    pass


if __name__ == "__main__":
    cli_group()