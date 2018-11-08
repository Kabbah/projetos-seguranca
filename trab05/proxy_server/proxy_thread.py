# ==============================================================================
# proxy_thread.py
#
# Autor: Victor Barpp Gomes
# Data: 23/10/2018
# ==============================================================================

import threading
import socket
import time
import traceback

from email.utils import formatdate

# ==============================================================================

UNAUTHORIZED_FILE = "unauthorized.html"

HTTP_PORT = 80

BUFFER_SIZE = 8192

# ==============================================================================

class ProxyThread(threading.Thread):
    """
    Thread que trata a conexão de um cliente.
    """
    def __init__(self, sock):
        super(ProxyThread, self).__init__()
        self.sock = sock

    # --------------------------------------------------------------------------

    def run(self):
        """
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
        """
        data, parsed_request = self.__get_socket_request()

        if data is None or parsed_request is None:
            self.sock.close()
            return

        print("Request: {}".format(parsed_request["Request-Line"]))

        try:
            host = parsed_request["Host"]
            method, filename, http_version = parsed_request["Request-Line"].split(" ")

            if method in ["HEAD", "GET", "POST", "PUT", "PATCH", "DELETE"]:
                if "monitorando" not in filename:
                    self.__forward_request(host, data)
                    print("Response: {}".format(parsed_request["Request-Line"]))
                else:
                    self.__send_unauthorized_page()
                    print("Unauthorized: {}".format(parsed_request["Request-Line"]))
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
        data = self.sock.recv(BUFFER_SIZE)
        return data

    # --------------------------------------------------------------------------

    def __get_socket_request(self):

        # Dados brutos
        data = b""

        # Cabeçalhos
        headers_b = b""

        # Lê os headers até encontrar um \r\n\r\n (final dos headers)
        content_bytes_read = 0
        while True:
            data += self.sock.recv(BUFFER_SIZE)
            if data == b"":
                return None, None

            rec_end = data.find(b"\r\n\r\n")
            if rec_end != -1:
                headers_b = data[:rec_end]
                content_bytes_read = len(data) - rec_end - 4
                break

        # Faz split dos headers
        request_line, headers = headers_b.split(b"\r\n", 1)
        request_headers = headers.split(b"\r\n")

        parsed_request = {"Request-Line": request_line.decode("utf-8")}
        for item in request_headers:
            try:
                key, value = item.split(b": ", 1)
                parsed_request[key.decode("utf-8")] = value.decode("utf-8")
            except ValueError:
                pass

        remaining_bytes = 0
        if "Content-Length" in parsed_request:
            remaining_bytes = int(parsed_request["Content-Length"]) - content_bytes_read

        while remaining_bytes > 0:
            chunk = self.sock.recv(BUFFER_SIZE)
            data += chunk
            remaining_bytes -= len(chunk)

        return data, parsed_request

    # --------------------------------------------------------------------------

    def __forward_request(self, host, request):
        if ":" in host:
            host, port = host.split(":")
            port = int(port)
        else:
            port = HTTP_PORT

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        sock.sendall(request)

        """
        total_data = []
        while True:
            data = sock.recv(8192)
            if not data:
                break
            total_data.append(data)
        """
        """
        timeout = 2
        sock.setblocking(False)

        begin = time.time()
        total_data = []
        while True:
            if total_data and time.time() - begin > timeout:
                break
            elif time.time() - begin > 2*timeout:
                break
            try:
                data = sock.recv(BUFFER_SIZE)
                if data:
                    total_data.append(data)
                    begin = time.time()
                else:
                    time.sleep(0.1)
            except:
                pass

        sock.close()

        response = b''.join(total_data)
        self.sock.send(response)
        """

        # Dados brutos
        data = b""

        # Cabeçalhos
        headers_b = b""

        # Conteúdo
        content = b""

        # Lê os headers até encontrar um \r\n\r\n (final dos headers)
        content_bytes_read = 0
        while True:
            chunk = sock.recv(BUFFER_SIZE)
            if chunk is None:
                if data == b"":
                    return None, None
                else:
                    # ???
                    break
            data += chunk
            self.sock.send(chunk)

            rec_end = data.find(b"\r\n\r\n")
            if rec_end != -1:
                headers_b = data[:rec_end]
                content = data[rec_end+4:]
                content_bytes_read = len(data) - rec_end - 4
                break

        # Faz split dos headers
        response_line, headers = headers_b.split(b"\r\n", 1)
        header_list = headers.split(b"\r\n")

        parsed_http = {"Response-Line": response_line.decode("utf-8")}
        for item in header_list:
            try:
                key, value = item.split(b": ", 1)
                parsed_http[key.decode("utf-8")] = value.decode("utf-8")
            except ValueError:
                pass

        if "Content-Length" in parsed_http:
            # Servidor respondeu o tamanho do conteúdo. Lê só o que falta.
            remaining_bytes = int(parsed_http["Content-Length"]) - content_bytes_read
            while remaining_bytes > 0:
                chunk = sock.recv(BUFFER_SIZE)
                data += chunk
                content += chunk
                self.sock.send(chunk)
                remaining_bytes -= len(chunk)
        elif "Transfer-Encoding" in parsed_http and parsed_http["Transfer-Encoding"] == "chunked":
            # Servidor não passou o tamanho do conteúdo, mas usa chunked encoding.
            # Não sei como tratar isso. Default para o modo porco.
            while True:
                chunk = sock.recv(BUFFER_SIZE)
                if chunk is None or len(chunk) == 0:
                    break
                data += chunk
                content += chunk
                self.sock.send(chunk)
        else:
            # Servidor não passou o tamanho e não usa chunked encoding, então deve
            # terminar a stream depois de enviar tudo.
            while True:
                chunk = sock.recv(BUFFER_SIZE)
                if chunk is None or len(chunk) == 0:
                    break
                data += chunk
                content += chunk
                self.sock.send(chunk)

        sock.close()

    # --------------------------------------------------------------------------

    def __get_socket_http_data(self, sock):

        # Dados brutos
        data = b""

        # Cabeçalhos
        headers_b = b""

        # Lê os headers até encontrar um \r\n\r\n (final dos headers)
        content_bytes_read = 0
        while True:
            data += sock.recv(BUFFER_SIZE)
            if data == b"":
                return None, None

            rec_end = data.find(b"\r\n\r\n")
            if rec_end != -1:
                headers_b = data[:rec_end]
                content_bytes_read = len(data) - rec_end - 4
                break

        # Faz split dos headers
        first_line, headers = headers_b.split(b"\r\n", 1)
        header_list = headers.split(b"\r\n")

        parsed_http = {"First-Line": first_line.decode("utf-8")}
        for item in header_list:
            try:
                key, value = item.split(b": ", 1)
                parsed_http[key.decode("utf-8")] = value.decode("utf-8")
            except ValueError:
                pass

        remaining_bytes = 0
        if "Content-Length" in parsed_http:
            remaining_bytes = int(parsed_http["Content-Length"]) - content_bytes_read

        while remaining_bytes > 0:
            chunk = self.sock.recv(BUFFER_SIZE)
            data += chunk
            remaining_bytes -= len(chunk)

        return data, parsed_http

    # --------------------------------------------------------------------------

    def __send_unauthorized_page(self):
        print("Sending unauthorized page.")

        date = formatdate(usegmt=True).encode()

        with open(UNAUTHORIZED_FILE, "r") as f:
            file_data = f.read().encode()

        # response = b"HTTP/1.0 200 OK\r\n" \
        response = b"HTTP/1.0 403 Forbidden\r\n" \
                   b"Date: " + date + b"\r\n" \
                   b"Server: Barpproxy/1.10.37 (custom)\r\n" \
                   b"Content-Type: text/html\r\n" \
                   b"Content-Length: " + str(len(file_data)).encode() + b"\r\n"  \
                   b"\r\n" + file_data + b"\r\n"

        self.sock.send(response)

# ==============================================================================
