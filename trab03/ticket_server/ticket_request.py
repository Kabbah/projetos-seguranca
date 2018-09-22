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
from google.protobuf.message import DecodeError
from message import TGSResponse_pb2
from message import UserTGSRequest_pb2

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
        msg = UserTGSRequest_pb2.UserTGSRequest()
        try:
            msg.ParseFromString(message)
        except DecodeError:
            return None
        request_des = msg.request
        ticket = msg.ticket

        # Descriptografa com DES
        des = pyDes.des(TGS_KEY[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        ticket_data = des.decrypt(ticket)
        try:
            ticket_data = ticket_data.decode("utf-8")
            ticket_data = json.loads(ticket_data)
        except (UnicodeDecodeError, ValueError):
            return None

        # Agora lê os campos internos
        user_id = ticket_data["id_c"]
        end_time = ticket_data["t_r"]
        key_client_tgs = bytes.fromhex(ticket_data["k_c_tgs"])

        # Agora é possível ler a requisição
        des = pyDes.des(key_client_tgs, pad=None, padmode=pyDes.PAD_PKCS5)
        request = des.decrypt(request_des)
        try:
            request = request.decode("utf-8")
            request = json.loads(request)
        except (UnicodeDecodeError, ValueError):
            return None

        # Agora lê os outros campos internos
        request_user_id = request["id_c"]
        service_id = request["id_s"]
        request_end_time = request["t_r"]
        random_n = request["n_2"]

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
        key_client_service = "".join("{:02x}".format(
                SystemRandom().getrandbits(8)) for _ in range(8))

        # Gera o ticket para comunicação entre o cliente e o serviço
        ticket = {"id_c": message_dict["id_c"],
                  "t_a": message_dict["t_r"],
                  "k_c_s": key_client_service}
        des = pyDes.des(message_dict["service"]["pw"][:8], pad=None,
                padmode=pyDes.PAD_PKCS5)
        ticket_des = des.encrypt(json.dumps(ticket))

        # Gera o restante da resposta
        user_header = {"k_c_s": key_client_service,
                       "t_a": message_dict["t_r"],
                       "n_2": message_dict["n_2"]}
        des = pyDes.des(message_dict["k_c_tgs"],
                        pad=None, padmode=pyDes.PAD_PKCS5)
        user_header_des = des.encrypt(json.dumps(user_header))

        # Junta a resposta e envia
        response = TGSResponse_pb2.TGSResponse()
        response.user_header = user_header_des
        response.ticket = ticket_des

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
