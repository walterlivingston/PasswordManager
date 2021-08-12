import base64
import os
from os import path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

master_pwd = input("What is the master password: ")

def generate_key():
    if path.exists("key.key"):
        with open("key.key", "rb") as key_file:
            key = key_file.read()
            if master_pwd in key.decode():
                return key
            else:
                raise SystemExit("Invalid Master Password!")

    else:
        key = Fernet.generate_key() + master_pwd.encode()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
            return key

fer = Fernet(generate_key())

def view():
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split("|")
            print("User: ", user, "| Password: ", fer.decrypt(passw.encode()).decode())


def add():
    name = input("Account Name: ")
    password = input("Password: ")

    with open("passwords.txt", "a") as f:
        f.write(name + "|" + fer.encrypt(password.encode()).decode() + "\n")


while True:
    mode = input(
        "Would you like to add a new password or view existing ones (view, add)? "
    )
    if mode == "q":
        break
    if mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid Mode.")
        continue
