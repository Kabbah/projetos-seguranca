# ==============================================================================
# REGISTRO DE SERVIÇOS NO TGS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================
"""
Este script serve apenas para simplificar a tarefa de "registrar" um serviço no
servidor de concessão de tickets. Em uma situação real, o registro de serviços
deveria ser feito de uma maneira melhor.
"""
# ==============================================================================

import getpass
import hashlib
import random
import tinydb

# ==============================================================================

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
SERVICES_FILE = "../services.json"

# ==============================================================================

def register_service():
    # Lê o arquivo de usuários
    services_data = tinydb.TinyDB(SERVICES_FILE)

    # Registro de um identificador
    identifier = input("Identifier: ")

    # Verifica se já existe alguém registrado com esse nome
    service_db = tinydb.Query()
    service_search = services_data.search(service_db["id"] == identifier)
    if len(service_search) > 0:
        print("Error: service already exists.")
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

    # Cria um dict com as informações do serviço
    #user_dict = {"username": username, "pw": hashed_pw, "pw_salt": pw_salt}
    service_dict = {"id": identifier, "pw": hashed_pw}

    # Adiciona o usuário à lista e grava no arquivo
    services_data.insert(service_dict)

def main():
    register_service()

if __name__ == "__main__":
    main()
