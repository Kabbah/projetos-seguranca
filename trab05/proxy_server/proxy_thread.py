# ==============================================================================
# proxy_thread.py
#
# Autor: Victor Barpp Gomes
# Data: 23/10/2018
# ==============================================================================

import multiprocessing
import requests
import traceback

from email.utils import formatdate

# ==============================================================================

UNAUTHORIZED_FILE = "unauthorized.html"

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
                        self.__forward_request(method, host, file)
                        #self.__send_unauthorized_page()
                    else:
                        self.__send_unauthorized_page()
        except Exception:
            traceback.print_exc()

        self.sock.close()

    # --------------------------------------------------------------------------

    @staticmethod
    def parse_http_request(request):
        request_str = request.decode()

        request_line, headers = request_str.split("\r\n", 1)
        request_headers = headers.split("\r\n")

        parsed_request = {"Request-Line": request_line}

        for item in request_headers:
            try:
                key, value = item.split(": ", 1)
                parsed_request[key] = value
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

    def __forward_request(self, method, host, file):
        response = requests.request(method, file)

        status_line = response.status_code
        header_data = response.headers.items()
        file_data = response.content
        date = formatdate(usegmt=True).encode()

        """
        response = b"HTTP/1.0 " + str(status_line).encode() + b"\r\n"
        for k, v in header_data:
            response += k.encode() + b": " + v.encode() + b"\r\n"
        response += b"\r\n" + file_data + b"\r\n"
        """

        response = b"HTTP/1.0 200 OK\r\n" \
                   b"Date: " + date + b"\r\n" \
                   b"Server: Barpproxy/1.10.37 (custom)\r\n" \
                   b"Content-Type: text/html\r\n" \
                   b"\r\n" + file_data + b"\r\n"

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
