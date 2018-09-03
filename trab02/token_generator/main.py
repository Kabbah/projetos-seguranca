# ==============================================================================
# main.py
#
# Autor: Victor Barpp Gomes
# Data: 2018-09-01
# ==============================================================================
"""
Descrição
"""
# ==============================================================================

import datetime
import getpass
import hashlib
import json
import os
import random

# ==============================================================================

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
USERS_FILE = "users.json"


# ==============================================================================

def register_user():
    # Lê o arquivo de usuários
    users_data = []
    if os.path.isfile(USERS_FILE):
        with open(USERS_FILE, "r") as users_file:
            users_data = json.loads(users_file.read())

    # Registro de um usuário
    username = input("Username: ")

    # Verifica se já existe alguém registrado com esse nome
    if any(user["username"] == username for user in users_data):
        print("Error: user already exists.")
        return

    # Obtém as senhas
    local_pw = getpass.getpass("Local password: ")
    seed_pw = getpass.getpass("Seed password: ")

    # Gera um salzinho com 4 caracteres
    salt = "".join(random.choice(ALPHABET) for i in range(4))

    # Calcula o hash da senha local
    sha = hashlib.sha256()
    sha.update(local_pw.encode("utf-8"))
    sha.update(salt.encode("utf-8"))
    hashed_local_pw = sha.hexdigest()

    # Calcula o hash da senha seed
    sha = hashlib.sha256()
    sha.update(seed_pw.encode("utf-8"))
    sha.update(salt.encode("utf-8"))
    hashed_seed_pw = sha.hexdigest()

    # Cria um dict com as informações do usuário
    user_dict = {"username": username, "local_pw": hashed_local_pw,
                 "seed_pw": hashed_seed_pw, "salt": salt}

    # Adiciona o usuário à lista e grava no arquivo
    users_data.append(user_dict)
    with open(USERS_FILE, "w") as users_file:
        json.dump(users_data, users_file)


# ==============================================================================

def generate_token():
    # Lê o usuário e a senha local
    username = input("Username: ")
    local_pw = getpass.getpass("Local password: ")

    # Lê o arquivo de usuários
    users_data = []
    if os.path.isfile(USERS_FILE):
        with open(USERS_FILE, "r") as users_file:
            users_data = json.loads(users_file.read())

    # Busca o usuário
    user = None
    for user_entry in users_data:
        if user_entry["username"] == username:
            user = user_entry
            break
    if user is None:
        print("Error: wrong username/password.")
        return

    # Calcula o hash da senha local
    sha = hashlib.sha256()
    sha.update(local_pw.encode("utf-8"))
    sha.update(user["salt"].encode("utf-8"))
    hashed_local_pw = sha.hexdigest()

    if user["local_pw"] != hashed_local_pw:
        print("Error: wrong username/password.")
        return

    # TODO: Gerar tokens
    tokens = []
    prev_token = user["seed_pw"]
    prev_token += user["salt"] + datetime.datetime.now().strftime("%Y%m%d%H%M")
    for i in range(5):
        sha = hashlib.sha256()
        sha.update(prev_token.encode("utf-8"))
        prev_token = sha.hexdigest()[:6]
        tokens.append(prev_token)

    print(tokens)


# ==============================================================================

def main():
    option = input("Menu:\n1 - Register new user\n2 - Generate tokens\nOption: ")
    if option == "1":
        register_user()
    elif option == "2":
        generate_token()


if __name__ == "__main__":
    main()

# ==============================================================================
