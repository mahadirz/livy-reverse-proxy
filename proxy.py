import argparse
import base64
import configparser
import gzip
import hashlib
import json
import logging
import pdb
import re
import select
import socket
import sys
import time
import traceback


class Config:
    def __init__(self, server_address, forward_to, shiro_path, log_level):
        self.buffer_size = 4096
        self.delay = 0.0001
        self.server_address = server_address
        self.forward_to = forward_to
        self.shiro_path = shiro_path
        self.log_level = log_level


class Shiro:
    def __init__(self, path):
        config = configparser.ConfigParser()
        config.read(path)
        self.users = self._extract_users(config)

    @staticmethod
    def _extract_users(config):
        return {
            user: {
                "iteration": int(auth_user[3]),
                "salt": auth_user[4],
                "hashed": auth_user[5]
            }
            for user, auth_user in ((user, config['users'][user].split(",")[0].split("$")) for user in config['users'])
        }

    def authenticate(self, user, password):
        """
        Original Code in Java https://github.com/apache/shiro/blob/b7253552e4fa12df4f40557087addba8888e147d/crypto/hash/src/main/java/org/apache/shiro/crypto/hash/SimpleHash.java#L387
        :param user:
        :param password:
        :return:
        """
        logging.debug("authenticate")
        if user not in self.users:
            return False

        hashed = self.users[user]
        logging.debug("hashed")
        logging.debug(hashed)

        m = hashlib.sha256()
        m.update(base64.b64decode(hashed['salt']))
        m.update(password.encode())
        digest = m.digest()

        for _ in range(hashed['iteration'] - 1):
            digest = hashlib.sha256(digest).digest()

        logging.debug("base64.b64encode(digest).decode()")
        logging.debug(base64.b64encode(digest).decode())
        return base64.b64encode(digest).decode() == hashed['hashed']


class ProxyServer:
    def __init__(self, config):
        self.config = config
        self.shiro = Shiro(config.shiro_path)
        self.input_list = []
        self.channel = {}
        self.server = self._init_server(*config.server_address)
        self.s = None

    def _init_server(self, host, port):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(200)
        return server

    def main_loop(self):
        self.input_list.append(self.server)
        while True:
            time.sleep(self.config.delay)
            inputready, _, _ = select.select(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(self.config.buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = self._init_forward(*self.config.forward_to)
        clientsock, clientaddr = self.server.accept()
        if forward:
            logging.info(f'{clientaddr[0]}:{clientaddr[1]} has connected')
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = {
                "socket": forward,
                "type": "client",
                "content_length": 0,
                "content_recv": 0,
                "content_encoding": None
            }
            self.channel[forward] = {"socket": clientsock, "type": "forward"}
        else:
            logging.warning(
                f"Can't establish connection with remote server. Closing connection with client side {clientaddr}")
            clientsock.close()

    @staticmethod
    def _init_forward(host, port):
        try:
            forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            forward.connect((host, int(port)))
            return forward
        except Exception:
            logging.error(traceback.format_exc())
            return False

    def on_close(self):
        logging.info(f"{self.s.getpeername()} has disconnected")
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s]["socket"])
        out = self.channel[self.s]["socket"]
        self.channel[out]["socket"].close()
        self.channel[self.s]["socket"].close()
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        if self.channel[self.s]['type'] == "client":
            logging.debug("on_recv from client:")
            logging.debug(self.s)
            self.process_client_data()
        else:
            self.channel[self.s]["socket"].sendall(self.data)
            logging.debug("on_recv from server:")
            logging.debug(self.s)
            logging.debug(self.data)

    def process_client_data(self):
        """
        Process data from client
        Since data can be bigger than the buffer size, we need to handle to read the data by chunk
        :return: 
        """
        try:
            logging.debug("DATA:")
            logging.debug(self.data)

            # default value
            original_body = self.data
            method = "GET"
            path = "/"

            # @todo use the content progress to directly forward the content
            logging.debug("Check for content receiving in progress")
            # content length should be equal to content_recv
            logging.debug(self.channel[self.s]["content_length"])
            logging.debug(self.channel[self.s]["content_recv"])

            content_encoding = self.channel[self.s]["content_encoding"]
            logging.debug("content_encoding:")
            logging.debug(content_encoding)

            if self.data[0:4] == b"POST" or self.data[0:3] == b"GET" or self.data[0:6] == b"DELETE":
                headers, original_body = self.data.split(b'\r\n\r\n', 1)
                header_lines = headers.decode().split('\r\n')
                method, path, _ = header_lines[0].split()
                logging.debug("header_lines")
                logging.debug(header_lines)
                logging.debug("original_body")
                logging.debug(original_body)
                headers = self.parse_headers(header_lines)
                logging.debug(headers)

                content_length = headers.get("Content-Length")
                self.channel[self.s]["content_length"] = content_length
                self.channel[self.s]["content_recv"] = 0  # reset
                self.channel[self.s]["content_encoding"] = headers.get('Content-Encoding')

            self.channel[self.s]["content_recv"] += len(original_body)
            body = gzip.decompress(original_body) if content_encoding == 'gzip' else original_body

            # the following lines can be refactored as plugin based
            if method == 'POST' and path.startswith('/sessions') and not re.match(r"\/sessions\/\d+?\/statements",
                                                                                  path):
                if not self.authenticate_request(headers, body):
                    return self.send_auth_error()
            self.channel[self.s]["socket"].sendall(self.data)
        except Exception:
            logging.error(traceback.format_exc())

    def authenticate_request(self, headers, body):
        content_type = headers.get('Content-Type')
        logging.debug(f"content_type: {content_type}")

        if content_type == 'application/json':
            post_data = json.loads(body)
            logging.debug("post_data")
            logging.debug(post_data)
            if 'proxyUser' in post_data and 'proxyPassword' in headers:
                return self.shiro.authenticate(post_data['proxyUser'], headers['proxyPassword'])
        return False

    @staticmethod
    def parse_headers(header_lines):
        headers = dict(map(str.strip, line.split(":", 1)) for line in header_lines[1:] if ":" in line)
        logging.debug("headers")
        logging.debug(headers)
        return headers

    def send_auth_error(self):
        error_message = 'Authentication Failed: Invalid proxyUser or proxyPassword'
        response = f'HTTP/1.1 401 Unauthorized Request\r\nContent-Type: text/plain\r\nContent-Length: {len(error_message)}\r\n\r\n{error_message}'
        self.s.sendall(response.encode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--server_address", nargs=2, default=('0.0.0.0', 8998), type=str, help="Server IP and port")
    parser.add_argument("--forward_to", nargs=2, default=('127.0.0.1', 8999), type=str,
                        help="Forwarding server IP and port")
    parser.add_argument("--shiro_path", default="/etc/zeppelin/conf/shiro.ini", type=str, help="Path to Shiro INI")
    parser.add_argument("--log_level", default='INFO', type=str, help="Logging level")
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    config = Config(args.server_address, args.forward_to, args.shiro_path, args.log_level)

    server = ProxyServer(config)
    try:
        logging.info(f"Listening to {config.server_address[0]}:{config.server_address[1]}")
        logging.info(f"Forwarding host {config.forward_to[0]}:{config.forward_to[1]}")
        server.main_loop()
    except KeyboardInterrupt:
        logging.info("Ctrl C - Stopping server")
        sys.exit(1)
