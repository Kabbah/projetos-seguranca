# ==============================================================================
# THREAD DE TRATAMENTO DE UMA CONEXÃO AO AS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

import json
import pyDes
import secrets
import tinydb
import threading

# ==============================================================================

# FIXME: colocar hash
TGS_KEY = ".S3cUr3^"

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
        # Carrega a mensagem como JSON
        msg = json.loads(message)
        username = msg["user_id"]
        request_des = bytes.fromhex(msg["request"])

        # Busca o usuário no banco de dados
        user_query = tinydb.Query()
        user_search = self.users_db.search(user_query["username"] == username)
        if len(user_search) == 0:
            return None

        # Descriptografa com DES
        user = user_search[0]
        des = pyDes.des(user["pw"][:8], pad=None, padmode=pyDes.PAD_PKCS5)
        request = des.decrypt(request_des)
        try:
            request = json.loads(request)
        except ValueError:
            return None

        # Agora lê os campos internos
        ret_dict = {"username": username,
                    "pw": user["pw"],
                    "service_id": request["service_id"],
                    "duration": request["duration"],
                    "random_n": request["random_n"]}
        return ret_dict

    # --------------------------------------------------------------------------

    def send_response(self, message_dict):
        # Gera a chave de sessão a ser usada com o TGS
        key_client_tgs = secrets.token_hex(8)

        # Gera o ticket para comunicação entre o cliente e o TGS
        ticket = {"username": message_dict["username"],
                  "duration": message_dict["duration"],
                  "session_key": key_client_tgs}
        des = pyDes.des(TGS_KEY, pad=None, padmode=pyDes.PAD_PKCS5)
        ticket_des = des.encrypt(json.dumps(ticket))

        # Gera o restante da resposta
        user_header = {"session_key": key_client_tgs,
                       "random_n": message_dict["random_n"]}
        print(message_dict["pw"][:8])
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
