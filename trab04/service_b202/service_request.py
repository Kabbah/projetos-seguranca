# ==============================================================================
# THREAD DE TRATAMENTO DE UMA CONEXÃO AO TGS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

import pyDes
import threading

# Protobuf
from Kerberos_pb2 import UserServiceRequest, UserServiceRequestData
from Kerberos_pb2 import TGSResponseTicket
from Kerberos_pb2 import ServiceResponse, ServiceResponseData
from google.protobuf.message import DecodeError

# ==============================================================================

KEY = "977565311fe59d9feafd0a9b25f3cc21f541c9eb9ee738c0b8550e821d5bee15"

# ==============================================================================

class ServiceRequest(threading.Thread):
    def __init__(self, sock):
        self.sock = sock
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
            resp = self.do_action(message_dict["id_c"], message_dict["s_r"])
            self.send_response(message_dict, resp)

        self.sock.close()

    # --------------------------------------------------------------------------

    def process_message(self, message):
        # Carrega a mensagem com Protobuf
        request = UserServiceRequest()
        try:
            request.ParseFromString(message)
        except DecodeError:
            return None

        # Descriptografa com DES
        des = pyDes.des(KEY[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        ticket_data = TGSResponseTicket()
        try:
            ticket_data_str = des.decrypt(request.t_c_s)
            if ticket_data_str == b'':
                return None
            ticket_data.ParseFromString(ticket_data_str)
        except (DecodeError, ValueError):
            return None

        # Agora lê os campos internos
        user_id = ticket_data.id_c
        authorized_time = ticket_data.t_a
        key_client_service = ticket_data.k_c_s

        # Agora é possível ler a requisição
        des = pyDes.des(key_client_service, pad=None, padmode=pyDes.PAD_PKCS5)
        request_data = UserServiceRequestData()
        try:
            request_data_str = des.decrypt(request.request)
            if request_data_str == b'':
                return None
            request_data.ParseFromString(request_data_str)
        except (UnicodeDecodeError, ValueError):
            return None

        # Agora lê os outros campos internos
        request_user_id = request_data.id_c
        request_end_time = request_data.t_r
        requested_service = request_data.s_r
        random_n = request_data.n_3

        if user_id != request_user_id:
            return None
        if request_end_time > authorized_time:
            return None

        # Verifica se o serviço requisitado é oferecido
        if requested_service not in ["open"]:
            return None

        ret_dict = {"id_c": user_id,
                    "n_3": random_n,
                    "k_c_s": key_client_service,
                    "s_r": requested_service}

        return ret_dict

    # --------------------------------------------------------------------------

    def send_response(self, message_dict, response):
        # Gera a resposta
        response_data = ServiceResponseData()
        response_data.response_str = response
        response_data.n_3 = message_dict["n_3"]
        des = pyDes.des(message_dict["k_c_s"],
                        pad=None, padmode=pyDes.PAD_PKCS5)
        des_response = des.encrypt(response_data.SerializeToString())

        # Junta a resposta e envia
        response = ServiceResponse()
        response.response = des_response

        self.sock.send(response.SerializeToString())

    # --------------------------------------------------------------------------

    def do_action(self, user_id, action):
        if action == "open":
            print("{}: Opened.".format(user_id))
            return "Opened"
        return "No action"

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
