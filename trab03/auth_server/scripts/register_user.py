# ==============================================================================
# REGISTRO DE USUÁRIOS PARA O AS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================
"""
Este script serve apenas para simplificar a tarefa de "registrar" um usuário no
servidor de autenticação. Em uma situação real, o registro de usuários deveria
ser feito de uma maneira melhor.
"""
# ==============================================================================

import getpass
import hashlib
import random
import tinydb

# ==============================================================================

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
USERS_FILE = "../users.json"

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

    # Obtém a senha
    pw = getpass.getpass("Password: ")

    # Gera um sal de 16 caracteres para a senha
    # FIXME:
    #     O servidor e o cliente precisam do hash da senha para a criptografia
    # simétrica. Como usar sal nesse sistema, para proteger o banco de dados de
    # usuários?
    #pw_salt = "".join(random.choice(ALPHABET) for _ in range(16))

    # Calcula o hash da senha
    sha = hashlib.sha256()
    sha.update(pw.encode("utf-8"))
    #sha.update(pw_salt.encode("utf-8"))
    hashed_pw = sha.hexdigest()

    # Cria um dict com as informações do usuário
    #user_dict = {"username": username, "pw": hashed_pw, "pw_salt": pw_salt}
    user_dict = {"username": username, "pw": hashed_pw}

    # Adiciona o usuário à lista e grava no arquivo
    users_data.insert(user_dict)

def main():
    register_user()

if __name__ == "__main__":
    main()
