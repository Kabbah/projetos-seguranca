# ==============================================================================
# THREAD DE TRATAMENTO DE UMA CONEXÃO AO TGS
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
from Kerberos_pb2 import UserTGSRequest, UserTGSRequestData
from Kerberos_pb2 import ASResponseTicket
from Kerberos_pb2 import TGSResponse, TGSResponseUserHeader, TGSResponseTicket
from google.protobuf.message import DecodeError

# ==============================================================================

TGS_KEY = "85378ff6e1f1a6ac931a653f36a2b3eb81beab1e8c78df8648dfc6f4cc99279d"

# ==============================================================================

class TicketRequest(threading.Thread):
    def __init__(self, sock, services_db):
        self.sock = sock
        self.services_db = services_db
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
        request = UserTGSRequest()
        try:
            request.ParseFromString(message)
        except DecodeError:
            return None

        # Descriptografa com DES
        des = pyDes.des(TGS_KEY[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        ticket_data = ASResponseTicket()
        try:
            ticket_data_str = des.decrypt(request.t_c_tgs)
            if ticket_data_str == b'':
                return None
            ticket_data.ParseFromString(ticket_data_str)
        except (DecodeError, ValueError):
            return None

        # Agora lê os campos internos
        user_id = ticket_data.id_c
        end_time = ticket_data.t_r
        key_client_tgs = ticket_data.k_c_tgs

        # Agora é possível ler a requisição
        des = pyDes.des(key_client_tgs, pad=None, padmode=pyDes.PAD_PKCS5)
        request_data = UserTGSRequestData()
        try:
            request_data_str = des.decrypt(request.request)
            if request_data_str == b'':
                return None
            request_data.ParseFromString(request_data_str)
        except (UnicodeDecodeError, ValueError):
            return None

        # Agora lê os outros campos internos
        request_user_id = request_data.id_c
        service_id = request_data.id_s
        request_end_time = request_data.t_r
        random_n = request_data.n_2

        # Busca o recurso no banco de dados
        service_query = tinydb.Query()
        service_search = self.services_db.search(
                service_query["id"] == service_id)
        if len(service_search) == 0:
            return None
        service = service_search[0]

        if user_id != request_user_id:
            return None
        if end_time != request_end_time:
            return None

        ret_dict = {"id_c": user_id,
                    "t_r": end_time,
                    "n_2": random_n,
                    "k_c_tgs": key_client_tgs,
                    "service": service}

        return ret_dict

    # --------------------------------------------------------------------------

    def send_response(self, message_dict):
        # Gera a chave de sessão a ser usada com o TGS
        key_client_service = bytes(SystemRandom().getrandbits(8)
                                   for _ in range(8))

        # TODO: Implementar aqui a política de tempo
        authorized_time = message_dict["t_r"]

        # Gera o ticket para comunicação entre o cliente e o serviço
        ticket = TGSResponseTicket()
        ticket.id_c = message_dict["id_c"]
        ticket.t_a = authorized_time
        ticket.k_c_s = key_client_service
        des = pyDes.des(message_dict["service"]["pw"][:8], pad=None,
                padmode=pyDes.PAD_PKCS5)
        des_ticket = des.encrypt(ticket.SerializeToString())

        # Gera o restante da resposta
        user_header = TGSResponseUserHeader()
        user_header.k_c_s = key_client_service
        user_header.t_a = authorized_time
        user_header.n_2 = message_dict["n_2"]
        des = pyDes.des(message_dict["k_c_tgs"],
                        pad=None, padmode=pyDes.PAD_PKCS5)
        des_user_header = des.encrypt(user_header.SerializeToString())

        # Junta a resposta e envia
        response = TGSResponse()
        response.user_header = des_user_header
        response.t_c_s = des_ticket

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
