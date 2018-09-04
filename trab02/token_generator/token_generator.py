# ==============================================================================
# token_generator.py
# GERADOR DE TOKENS (ONE TIME PASSWORDS)
#
# Autor: Victor Barpp Gomes
# Data: 2018-09-01
# ==============================================================================
"""
Este script implementa um gerador de tokens para uso com o app.py. Os usuários
são salvos no arquivo users.json.
"""
# ==============================================================================

import datetime
import getpass
import hashlib
import random
import tinydb

# ==============================================================================

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
USERS_FILE = "users.json"

# ==============================================================================

def register_user():
    # Lê o arquivo de usuários
    users_data = tinydb.TinyDB(USERS_FILE)

    # Registro de um usuário
    username = input("Username: ")

    # Verifica se já existe alguém registrado com esse nome
    user_db = tinydb.Query()
    user_search = users_data.search(user_db["username"] == username)
    if len(user_search) > 0:
        print("Error: user already exists.")
        return

    # Obtém as senhas
    local_pw = getpass.getpass("Local password: ")
    seed_pw = getpass.getpass("Seed password: ")

    # Gera um sal de 16 caracteres para cada senha
    local_pw_salt = "".join(random.choice(ALPHABET) for i in range(16))
    seed_pw_salt = "".join(random.choice(ALPHABET) for i in range(16))

    # Gera um salzinho com 4 caracteres
    salt = "".join(random.choice(ALPHABET) for i in range(4))

    # Calcula o hash da senha local
    sha = hashlib.sha256()
    sha.update(local_pw.encode("utf-8"))
    sha.update(local_pw_salt.encode("utf-8"))
    hashed_local_pw = sha.hexdigest()

    # Calcula o hash da senha seed
    sha = hashlib.sha256()
    sha.update(seed_pw.encode("utf-8"))
    sha.update(seed_pw_salt.encode("utf-8"))
    hashed_seed_pw = sha.hexdigest()

    # Cria um dict com as informações do usuário
    user_dict = {"username": username,
                 "local_pw": hashed_local_pw, "local_pw_salt": local_pw_salt,
                 "seed_pw": hashed_seed_pw, "seed_pw_salt": seed_pw_salt,
                 "token_salt": salt, "last_login": 0}

    # Adiciona o usuário à lista e grava no arquivo
    users_data.insert(user_dict)

# ==============================================================================

def generate_token():
    # Lê o arquivo de usuários
    users_data = tinydb.TinyDB(USERS_FILE)

    # Lê o usuário e a senha local
    username = input("Username: ")
    local_pw = getpass.getpass("Local password: ")

    # Busca o usuário
    user_db = tinydb.Query()
    user_search = users_data.search(user_db["username"] == username)
    if len(user_search) == 0:
        print("Error: wrong username/password.")
        return
    user = user_search[0]

    # Calcula o hash da senha local com o sal dela
    sha = hashlib.sha256()
    sha.update(local_pw.encode("utf-8"))
    sha.update(user["local_pw_salt"].encode("utf-8"))
    hashed_local_pw = sha.hexdigest()

    if user["local_pw"] != hashed_local_pw:
        print("Error: wrong username/password.")
        return

    # Gera tokens usando a senha semente, o sal de token e o tempo
    tokens = []
    prev_token = user["seed_pw"]
    prev_token += user["token_salt"] + datetime.datetime.now().strftime("%Y%m%d%H%M")
    for i in range(5):
        sha = hashlib.sha256()
        sha.update(prev_token.encode("utf-8"))
        prev_token = sha.hexdigest()[:6]
        tokens.append(prev_token)

    print("Tokens: " + str(tokens))

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
