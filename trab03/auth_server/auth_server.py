# ==============================================================================
# SERVIDOR DE AUTENTICAÇÃO (AS) ESTILO KERBEROS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

import socket
import tinydb

from auth_request import AuthRequest

# ==============================================================================

USERS_FILE = "users.json"
PORT_USER_APP = 11036
PORT_AUTH_SERVER = 11037
PORT_TICKET_SERVER = 11038

# ==============================================================================

class AuthServer(object):
    def __init__(self, port=PORT_AUTH_SERVER):
        self.port = port
        self.users_db = tinydb.TinyDB(USERS_FILE)

    # --------------------------------------------------------------------------

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((socket.gethostname(), self.port))
        server_socket.listen(5)

        while True:
            (sock, address) = server_socket.accept()
            new_thread = AuthRequest(sock, self.users_db)
            new_thread.start()

# ==============================================================================
