# ==============================================================================
# SERVIDOR DE CONCESSÃO DE TICKETS (TGS) ESTILO KERBEROS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

import socket
import tinydb

from ticket_request import TicketRequest

# ==============================================================================

SERVICES_FILE = "services.json"
PORT_USER_APP = 11036
PORT_AUTH_SERVER = 11037
PORT_TICKET_SERVER = 11038

# ==============================================================================

class TicketServer(object):
    def __init__(self, port=PORT_TICKET_SERVER):
        self.port = port
        self.services_db = tinydb.TinyDB(SERVICES_FILE)

    # --------------------------------------------------------------------------

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((socket.gethostname(), self.port))
        server_socket.listen(5)

        while True:
            (sock, address) = server_socket.accept()
            new_thread = TicketRequest(sock, self.services_db)
            new_thread.start()

# ==============================================================================
