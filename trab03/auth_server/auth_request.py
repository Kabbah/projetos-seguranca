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
        message = message.decode("utf-8") # Verificar exceções disso aqui

        # Tenta processar a mensagem
        message_dict = self.process_message(message)
        if message_dict is None:
            self.sock.send(b"Request denied")
        else:
            self.send_response(message_dict)

        self.sock.close()

    # --------------------------------------------------------------------------

    def process_message(self, message):
        # Carrega a mensagem como JSON
        msg = json.loads(message)
        username = msg["id_c"]
        request_des = bytes.fromhex(msg["request"])

        # Busca o usuário no banco de dados
        user_query = tinydb.Query()
        user_search = self.users_db.search(user_query["username"] == username)
        if len(user_search) == 0:
            return None
        
        # FIXME: verificar se o hash da senha é idêntico?

        # Descriptografa com DES
        user = user_search[0]
        des = pyDes.des(user["pw"][:8], pad=None, padmode=pyDes.PAD_PKCS5)
        request = des.decrypt(request_des)
        request = request.decode("utf-8") # Verificar exceções disso aqui
        try:
            request = json.loads(request) # Verificar exceções disso aqui
        except ValueError:
            return None

        # Agora lê os campos internos
        ret_dict = {"id_c": username,
                    "pw": user["pw"],
                    "id_s": request["id_s"],
                    "t_r": request["t_r"],
                    "n_1": request["n_1"]}
        return ret_dict

    # --------------------------------------------------------------------------

    def send_response(self, message_dict):
        # Gera a chave de sessão a ser usada com o TGS
        seusbytes = bytes(SystemRandom().getrandbits(8) for _ in range(8))
        key_client_tgs = "".join("{:02x}".format(SystemRandom().getrandbits(8))
                for _ in range(8))

        # Gera o ticket para comunicação entre o cliente e o TGS
        ticket = {"id_c": message_dict["id_c"],
                  "t_r": message_dict["t_r"],
                  "k_c_tgs": key_client_tgs}
        des = pyDes.des(TGS_KEY[:8], pad=None, padmode=pyDes.PAD_PKCS5)
        ticket_des = des.encrypt(json.dumps(ticket))

        # Gera o restante da resposta
        user_header = {"k_c_tgs": key_client_tgs,
                       "n_1": message_dict["n_1"]}
        des = pyDes.des(message_dict["pw"][:8],
                        pad=None, padmode=pyDes.PAD_PKCS5)
        sarue_des = des.encrypt(json.dumps(user_header))

        # Junta a resposta e envia
        ret_dict = {"user_header": sarue_des.hex(), "ticket": ticket_des.hex()}
        self.sock.send(json.dumps(ret_dict).encode())

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
