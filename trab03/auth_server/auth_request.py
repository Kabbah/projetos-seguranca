# ==============================================================================
# THREAD DE TRATAMENTO DE UMA CONEXÃO AO AS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

import json
import pyDes
import tinydb
import threading

from random import SystemRandom

# Protobuf
from Kerberos_pb2 import UserASRequest, UserASRequestData
from Kerberos_pb2 import ASResponse, ASResponseUserHeader, ASResponseTicket
from google.protobuf.message import DecodeError

# ==============================================================================

TGS_KEY = "85378ff6e1f1a6ac931a653f36a2b3eb81beab1e8c78df8648dfc6f4cc99279d"

# ==============================================================================

class AuthRequest(threading.Thread):
    def __init__(self, sock, users_db):
        self.sock = sock
        self.users_db = users_db
        threading.Thread.__init__(self)

    # --------------------------------------------------------------------------

    def run(self):
        # Recebe a mensagem enviada por socket
        message = self.socket_recv()

        # Tenta processar a mensagem
        message_dict = self.process_message(message)
        if message_dict is None:
            self.sock.send(b"Request denied")
        else:
            self.send_response(message_dict)

        self.sock.close()

    # --------------------------------------------------------------------------

    def process_message(self, message):
        # Carrega a mensagem com Protobuf
        request = UserASRequest()
        try:
            request.ParseFromString(message)
        except DecodeError:
            return None
        username = request.id_c

        # Busca o usuário no banco de dados
        user_query = tinydb.Query()
        user_search = self.users_db.search(user_query["username"] == username)
        if len(user_search) == 0:
            return None

        # Descriptografa com DES
        user = user_search[0]
        des = pyDes.des(user["pw"][:8], pad=None, padmode=pyDes.PAD_PKCS5)
        request_data = UserASRequestData()
        try:
            request_data_str = des.decrypt(request.request)
            if request_data_str == b'':
                return None
            request_data.ParseFromString(request_data_str)
        except (DecodeError, ValueError):
            return None

        # Agora lê os campos internos
        ret_dict = {"id_c": username,
                    "pw": user["pw"],
                    "id_s": request_data.id_s,
                    "t_r": request_data.t_r,
                    "n_1": request_data.n_1}
        return ret_dict

    # --------------------------------------------------------------------------

    def send_response(self, message_dict):
        # Gera a chave de sessão a ser usada com o TGS
        key_client_tgs = bytes(SystemRandom().getrandbits(8) for _ in range(8))

        # Gera o ticket para comunicação entre o cliente e o TGS
        ticket = ASResponseTicket()
        ticket.id_c = message_dict["id_c"]
        ticket.t_r = message_dict["t_r"]
        ticket.k_c_tgs = key_client_tgs
        des = pyDes.des(TGS_KEY[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        des_ticket = des.encrypt(ticket.SerializeToString())

        # Gera o restante da resposta
        user_header = ASResponseUserHeader()
        user_header.k_c_tgs = key_client_tgs
        user_header.n_1 = message_dict["n_1"]
        des = pyDes.des(message_dict["pw"][:8],
                        pad=None, padmode=pyDes.PAD_PKCS5)
        des_user_header = des.encrypt(user_header.SerializeToString())

        # Junta a resposta e envia
        response = ASResponse()
        response.user_header = des_user_header
        response.t_c_tgs = des_ticket

        self.sock.send(response.SerializeToString())

    # --------------------------------------------------------------------------

    def socket_recv(self, buffer_size=2048):
        chunks = []
        while True:
            chunk = self.sock.recv(buffer_size)
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
