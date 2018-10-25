# ==============================================================================
# proxy_server.py
#
# Autor: Victor Barpp Gomes
# Data: 23/10/2018
# ==============================================================================

import socket

from proxy_thread import ProxyThread

# ==============================================================================

PROXY_HOSTNAME = "192.168.100.2"
PROXY_PORT = 8000

# ==============================================================================

class ProxyServer(object):
    """
    Esta classe representa o servidor proxy, e sua função é receber conexões a
    partir do navegador dos clientes.
    """

    def __init__(self, hostname=PROXY_HOSTNAME, port=PROXY_PORT):
        """
        Apenas inicializa o socket do servidor proxy, mas não aguarda conexão.
        :param port: porta
        :type port: int
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((hostname, port))
        self.server_socket.listen(5)

    # --------------------------------------------------------------------------

    def run(self):
        while True:
            (sock, address) = self.server_socket.accept()

            print("Proxy: connection from " + str(address))
            new_thread = ProxyThread(sock)
            new_thread.start()

# ==============================================================================
