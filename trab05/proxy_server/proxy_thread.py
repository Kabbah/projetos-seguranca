# ==============================================================================
# proxy_thread.py
#
# Autor: Victor Barpp Gomes
# Data: 23/10/2018
# ==============================================================================

import multiprocessing
import requests
import socket
import traceback

from email.utils import formatdate

# ==============================================================================

UNAUTHORIZED_FILE = "unauthorized.html"

HTTP_PORT = 80

# ==============================================================================

class ProxyThread(multiprocessing.Process):
    """
    Thread que trata a conexão de um cliente.
    """
    def __init__(self, sock):
        multiprocessing.Process.__init__(self)
        self.sock = sock

    # --------------------------------------------------------------------------

    def run(self):
        data = self.__get_socket_data()
        print(data)

        try:
            parsed_request = ProxyThread.parse_http_request(data)

            if parsed_request is not None:
                host = parsed_request["Host"]
                method, file, http_version = parsed_request["Request-Line"].split(" ")

                if method in ["HEAD", "GET", "POST", "PUT", "PATCH", "DELETE"]:
                    if "monitorando" not in file:
                        self.__forward_request(host, data)
                        #self.__send_unauthorized_page()
                    else:
                        self.__send_unauthorized_page()
        except Exception:
            traceback.print_exc()

        self.sock.close()

    # --------------------------------------------------------------------------

    @staticmethod
    def parse_http_request(request):
        request_str = request#.decode()

        request_line, headers = request_str.split(b"\r\n", 1)
        request_headers = headers.split(b"\r\n")

        parsed_request = {"Request-Line": request_line.decode("utf-8")}

        for item in request_headers:
            try:
                key, value = item.split(b": ", 1)
                parsed_request[key.decode("utf-8")] = value.decode("utf-8")
            except ValueError:
                pass

        return parsed_request

    # --------------------------------------------------------------------------

    def __get_socket_data(self):
        """
        data = b""
        while True:
            chunk = self.sock.recv(1024)
            if not chunk:
                break
            data += chunk
        """
        data = self.sock.recv(8192)
        return data

    # --------------------------------------------------------------------------

    def __forward_request(self, host, request):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, HTTP_PORT))

        sock.sendall(request)

        total_data=[]
        while True:
            data = sock.recv(8192)
            if not data:
                break
            total_data.append(data)

        sock.close()

        response = b''.join(total_data)
        self.sock.send(response)

    # --------------------------------------------------------------------------

    def __send_unauthorized_page(self):
        print("Sending unauthorized page.")

        date = formatdate(usegmt=True).encode()

        with open(UNAUTHORIZED_FILE, "r") as f:
            file_data = f.read().encode()

        # response = b"HTTP/1.0 200 OK\r\n" \
        response = b"HTTP/1.0 401 Unauthorized\r\n" \
                   b"Date: " + date + b"\r\n" \
                   b"Server: Barpproxy/1.10.37 (custom)\r\n" \
                   b"Content-Type: text/html\r\n" \
                   b"\r\n" + file_data + b"\r\n"

        self.sock.send(response)

# ==============================================================================
