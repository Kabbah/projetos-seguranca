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
from Kerberos_pb2 import UserASRequest, UserASRequestData
from Kerberos_pb2 import ASResponse, ASResponseUserHeader
from Kerberos_pb2 import UserTGSRequest, UserTGSRequestData
from Kerberos_pb2 import TGSResponse, TGSResponseUserHeader
from Kerberos_pb2 import UserServiceRequest, UserServiceRequestData
from Kerberos_pb2 import ServiceResponse
from google.protobuf.message import DecodeError

# ==============================================================================

PORT_AUTH_SERVER = 11037
PORT_TICKET_SERVER = 11038

VERBOSE = True

# ==============================================================================

class UserApp(object):
    def __init__(self):
        pass

    # --------------------------------------------------------------------------

    def start(self):
        # Pega nome de usuário e senha por input
        username = input("Username: ")
        hashed_pw = hashlib.sha256(
            getpass("Password: ").encode("utf-8")).hexdigest()

        # Pega ID do serviço e duração do ticket por input
        service_id = input("Service ID: ")
        duration = int(input("Duration (minutes): "))

        # Calcula o timestamp final a partir da duração
        end_time = time.time() + 60 * duration

        # ==================== #
        # Comunicação com o AS #
        # ==================== #

        # Monta a requisição para o AS
        request, random_n = self.make_request_as(username, hashed_pw,
                service_id, end_time)

        # Cria o socket e tenta enviar a requisição ao AS
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((socket.gethostname(), PORT_AUTH_SERVER))
        if client_socket.send(request.SerializeToString()) == 0:
            raise RuntimeError("Socket connection broken: AS")

        # Aguarda a resposta do AS e processa
        response = self.socket_recv(client_socket)
        client_socket.close()
        key_client_tgs, ticket_tgs = self.process_response_as(response,
                hashed_pw, random_n)

        # Verifica se a comunicação com o AS foi bem sucedida
        if key_client_tgs is None or ticket_tgs is None:
            print("Failed to communicate with the AS")
            return

        # ===================== #
        # Comunicação com o TGS #
        # ===================== #

        # Monta uma requisição para o TGS
        request, random_n = self.make_request_tgs(username, service_id,
                end_time, key_client_tgs, ticket_tgs)

        # Cria o socket e tenta enviar a requisição ao TGS
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((socket.gethostname(), PORT_TICKET_SERVER))
        if client_socket.send(request.SerializeToString()) == 0:
            raise RuntimeError("Socket connection broken: TGS")

        # Aguarda a resposta do TGS e processa
        response = self.socket_recv(client_socket)
        client_socket.close()
        key_client_service, ticket_service = self.process_response_tgs(response,
                key_client_tgs, random_n)

        # Verifica se a comunicação com o TGS foi bem sucedida
        if key_client_service is None or ticket_service is None:
            print("Failed to communicate with the TGS")
            return

    # --------------------------------------------------------------------------

    @staticmethod
    def make_request_as(user_id, user_pw_hash, service_id, end_time):
        """Monta uma requisição a partir dos dados fornecidos.
        A requisição é uma mensagem Protobuf que contém os seguintes atributos:
            id_c: string que representa o nome do usuário
            request: bytes que representam um dicionário encriptado com DES.
                     Este dicionário contém id_s (ID do serviço), t_r (duração)
                     e n_1 (número aleatório 1).

        :param user_id: username do usuário
        :param user_pw_hash: hash SHA-256 da senha do usuário
        :param service_id: identificador do serviço desejado
        :param end_time: tempo desejado
        :return: request (mensagem Protobuf) e random_n (número aleatório 1)
        """
        # Gera o número aleatório da mensagem
        random_n = bytes(SystemRandom().getrandbits(8) for _ in range(8))

        # Monta a parte a ser criptografada da requisição
        request_data = UserASRequestData()
        request_data.id_s = service_id
        request_data.t_r = end_time
        request_data.n_1 = random_n

        if VERBOSE:
            print("\nAS request data:\n{}\n".format(request_data))

        # Criptografa usando DES
        des = pyDes.des(user_pw_hash[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        des_request_data = des.encrypt(request_data.SerializeToString())

        # Monta o request com Protobuf
        request = UserASRequest()
        request.id_c = user_id
        request.request = des_request_data

        if VERBOSE:
            print("AS request message:\n{}\n".format(request))

        return request, random_n

    # --------------------------------------------------------------------------

    @staticmethod
    def process_response_as(response, user_pw_hash, random_n):
        if VERBOSE:
            print("AS response:\n{}\n".format(response))

        # Lê a resposta com Protobuf
        resp = ASResponse()
        try:
            resp.ParseFromString(response)
        except DecodeError:
            return None, None

        # Tenta descriptografar o header, que contém a chave de sessão e o
        # número aleatório gerado na mensagem de requisição
        des = pyDes.des(user_pw_hash[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        user_header = ASResponseUserHeader()
        try:
            user_header_str = des.decrypt(resp.user_header)
            if user_header_str == b'':
                return None, None
            user_header.ParseFromString(user_header_str)
        except (DecodeError, ValueError):
            return None, None

        if VERBOSE:
            print("Data received from AS:\n{}\n".format(user_header))

        if user_header.n_1 != random_n:
            return None, None

        # Retorna a chave de sessão e o ticket para se comunicar com o TGS
        return user_header.k_c_tgs, resp.t_c_tgs

    # --------------------------------------------------------------------------

    @staticmethod
    def make_request_tgs(user_id, service_id, end_time, key_client_tgs, ticket_tgs):
        # Gera o número aleatório da mensagem
        random_n = bytes(SystemRandom().getrandbits(8) for _ in range(8))

        # Monta a parte a ser criptografada da requisição
        request_data = UserTGSRequestData()
        request_data.id_c = user_id
        request_data.id_s = service_id
        request_data.t_r = end_time
        request_data.n_2 = random_n

        if VERBOSE:
            print("\nTGS request data:\n{}\n".format(request_data))

        # Criptografa usando DES
        des = pyDes.des(key_client_tgs, pad=None, padmode=pyDes.PAD_PKCS5)
        des_request_data = des.encrypt(request_data.SerializeToString())

        # Monta o request com Protobuf
        request = UserTGSRequest()
        request.request = des_request_data
        request.t_c_tgs = ticket_tgs

        if VERBOSE:
            print("TGS request message:\n{}\n".format(request))

        return request, random_n

    # --------------------------------------------------------------------------

    @staticmethod
    def process_response_tgs(response, key_client_tgs, random_n):
        if VERBOSE:
            print("TGS response:\n{}\n".format(response))

        # Lê a resposta com Protobuf
        resp = TGSResponse()
        try:
            resp.ParseFromString(response)
        except DecodeError:
            return None, None

        # Tenta descriptografar o header, que contém a chave de sessão e o
        # número aleatório gerado na mensagem de requisição
        des = pyDes.des(key_client_tgs, pad=None, padmode=pyDes.PAD_PKCS5)
        user_header = TGSResponseUserHeader()
        try:
            user_header_str = des.decrypt(resp.user_header)
            if user_header_str == b'':
                return None, None
            user_header.ParseFromString(user_header_str)
        except (DecodeError, ValueError):
            return None, None

        if VERBOSE:
            print("Data received from TGS:\n{}\n".format(user_header))

        if user_header.n_2 != random_n:
            return None, None

        # Retorna a chave de sessão e o ticket para se comunicar como o serviço
        return user_header.k_c_s, resp.t_c_s

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
