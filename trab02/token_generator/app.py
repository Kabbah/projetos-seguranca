# ==============================================================================
# app.py
# APLICATIVO CUJO ACESSO É LIBERADO POR TOKEN (ONE TIME PASSWORD)
#
# Autor: Victor Barpp Gomes
# Data: 2018-09-03
# ==============================================================================
"""
Este script implementa a autenticação por token. Os usuários estão salvos no
arquivo users.json.
"""
# ==============================================================================

import datetime
import hashlib
import tinydb

# ==============================================================================

USERS_FILE = "users.json"

# ==============================================================================

def check_token(username, token):
    # Lê o arquivo de usuários
    users_data = tinydb.TinyDB(USERS_FILE)

    # Busca o usuário
    user_db = tinydb.Query()
    user_search = users_data.search(user_db["username"] == username)
    if len(user_search) == 0:
        # Usuário não existe
        return False
    user = user_search[0]

    # Gera tokens
    tokens = []
    prev_token = user["seed_pw"]
    prev_token += user["token_salt"] + datetime.datetime.now().strftime("%Y%m%d%H%M")
    for i in range(5):
        sha = hashlib.sha256()
        sha.update(prev_token.encode("utf-8"))
        prev_token = sha.hexdigest()[:6]
        if prev_token == user["last_token"]:
            break
        tokens.append(prev_token)

    # Valida ou não o token fornecido
    if token in tokens:
        users_data.update({"last_token": token}, user_db["username"] == username)
        return True
    return False

# ==============================================================================

def main():
    # Lê o usuário e o token
    username = input("Username: ")
    token = input("Token: ")

    # Verifica o token
    auth = check_token(username, token)
    if auth:
        print("Success: valid token")
    else:
        print("Error: invalid username/token")

if __name__ == "__main__":
    main()

# ==============================================================================
