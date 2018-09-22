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
        duration = input("Duration (minutes): ")

        # Monta a requisição para o AS
        request = self.make_request(username, hashed_pw, service_id, duration)

        # Cria o socket e tenta enviar a requisição ao AS
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((socket.gethostname(), PORT_AUTH_SERVER))
        if client_socket.send(request) == 0:
            raise RuntimeError("Socket connection broken")

        # Aguarda a resposta do AS e processa
        response = self.socket_recv(client_socket)
        self.process_response(response, hashed_pw)

    # --------------------------------------------------------------------------

    def make_request(self, user_id, user_pw_hash, service_id, duration):
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
        return request.SerializeToString()

    # --------------------------------------------------------------------------

    def process_response(self, response, user_pw_hash):
        # Lê a resposta com Protobuf
        resp = ASResponse_pb2.ASResponse()
        try:
            resp.ParseFromString(response)
        except DecodeError:
            # FIXME
            raise

        # Tenta descriptografar o header, que contém a chave de sessão e o
        # número aleatório gerado na mensagem de requisição
        des = pyDes.des(user_pw_hash[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        # Verificar exceções da linha abaixo
        user_header = des.decrypt(resp.user_header).decode("utf-8")
        try:
            user_header = json.loads(user_header)
        except ValueError:
            # FIXME
            raise

        # FIXME
        print(user_header["k_c_tgs"])
        print(user_header["n_1"])
        print(resp.ticket)

        # TODO:
        # Verificar se o número é o mesmo da requisição.
        # Converter os campos hexadecimais (ASCII) para vetores de bytes

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
