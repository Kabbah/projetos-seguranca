# ==============================================================================
# PROGRAMA USUÁRIO QUE ACESSA OS SERVIDORES AS, TGS E SERVIÇOS.
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

import hashlib
import json
import pyDes
import socket
import time

from getpass import getpass
from random import SystemRandom

# Protobuf
from google.protobuf.message import DecodeError
from message import ASResponse_pb2
from message import UserASRequest_pb2

# ==============================================================================

PORT_USER_APP = 11036
PORT_AUTH_SERVER = 11037
PORT_TICKET_SERVER = 11038

# ==============================================================================

class UserApp(object):
    def __init__(self, port=PORT_USER_APP):
        self.port = port

    # --------------------------------------------------------------------------

    def start(self):
        # Pega nome de usuário e senha por input
        username = input("Username: ")
        hashed_pw = hashlib.sha256(
            getpass("Password: ").encode("utf-8")).hexdigest()

        # Pega ID do serviço e duração do ticket por input
        service_id = input("Service ID: ")
        duration = int(input("Duration (minutes): "))

        # Monta a requisição para o AS
        request, random_n = self.make_request(username, hashed_pw, service_id,
                                              duration)

        # Cria o socket e tenta enviar a requisição ao AS
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((socket.gethostname(), PORT_AUTH_SERVER))
        if client_socket.send(request.SerializeToString()) == 0:
            raise RuntimeError("Socket connection broken")

        # Aguarda a resposta do AS e processa
        response = self.socket_recv(client_socket)
        key_client_tgs, ticket_tgs = self.process_response(response, hashed_pw,
                                                           random_n)

        # Verifica se a comunicação com o AS foi bem sucedida
        if key_client_tgs is None or ticket_tgs is None:
            print("Erro na comunicação com o AS.")
            return

    # --------------------------------------------------------------------------

    def make_request(self, user_id, user_pw_hash, service_id, duration):
        """Monta uma requisição a partir dos dados fornecidos.
        A requisição é uma mensagem Protobuf que contém os seguintes atributos:
            id_c: string que representa o nome do usuário
            request: bytes que representam um dicionário encriptado com DES.
                     Este dicionário contém id_s (ID do serviço), t_r (duração)
                     e n_1 (número aleatório 1).

        :param user_id: username do usuário
        :param user_pw_hash: hash SHA-256 da senha do usuário
        :param service_id: identificador do serviço desejado
        :param duration: tempo desejado
        :return: request (mensagem Protobuf) e random_n (número aleatório 1)
        """
        # Calcula o timestamp final a partir da duração
        duration = time.time() + 60*duration

        # Monta a parte a ser criptografada da requisição
        random_n = "".join("{:02x}".format(SystemRandom().getrandbits(8))
                for _ in range(16))
        request_data = {"id_s": service_id,
                        "t_r": duration,
                        "n_1": random_n}
        request_data_str = json.dumps(request_data)

        # Criptografa usando DES
        des = pyDes.des(user_pw_hash[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        des_request_str = des.encrypt(request_data_str)

        # Monta o request com Protobuf
        request = UserASRequest_pb2.UserASRequest()
        request.id_c = user_id
        request.request = des_request_str
        return request, random_n

    # --------------------------------------------------------------------------

    def process_response(self, response, user_pw_hash, random_n):
        # Lê a resposta com Protobuf
        resp = ASResponse_pb2.ASResponse()
        try:
            resp.ParseFromString(response)
        except DecodeError:
            return None, None

        # Tenta descriptografar o header, que contém a chave de sessão e o
        # número aleatório gerado na mensagem de requisição
        des = pyDes.des(user_pw_hash[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        # Verificar exceções da linha abaixo
        user_header = des.decrypt(resp.user_header).decode("utf-8")
        try:
            user_header = json.loads(user_header)
        except ValueError:
            return None, None

        # Dados recebidos
        key_client_tgs = bytes.fromhex(user_header["k_c_tgs"])
        recv_random_n = user_header["n_1"]
        ticket = resp.ticket

        if recv_random_n != random_n:
            return None, None

        # FIXME
        print(key_client_tgs)
        print(ticket)

        return key_client_tgs, ticket

    # --------------------------------------------------------------------------

    def socket_recv(self, sock, buffer_size=2048):
        chunks = []
        while True:
            chunk = sock.recv(buffer_size)
            if chunk:
                chunks.append(chunk)
                # FIXME:
                # O programa vai se enforcar se o tamanho da mensagem for um
                # múltiplo de buffer_size...
                # Colocar timeout?
                if len(chunk) < buffer_size:
                    break
            else:
                break
        return b''.join(chunks)

# ==============================================================================
