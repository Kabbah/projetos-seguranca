# ==============================================================================
# SERVIDOR DE CONCESSÃO DE TICKETS (TGS) ESTILO KERBEROS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

import socket

from service_request import ServiceRequest

# ==============================================================================

PORT_SERVICE = 11039

# ==============================================================================

class ServiceServer(object):
    def __init__(self, port=PORT_SERVICE):
        self.port = port

    # --------------------------------------------------------------------------

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((socket.gethostname(), self.port))
        server_socket.listen(5)

        while True:
            (sock, address) = server_socket.accept()
            new_thread = ServiceRequest(sock)
            new_thread.start()

# ==============================================================================
