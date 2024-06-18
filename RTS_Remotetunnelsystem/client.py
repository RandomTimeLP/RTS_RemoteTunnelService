import socket
import time
import re
import sys
import logging
import json
import threading
import asyncio
from ExtraDecorators import validatetyping
import ExtraUtils.timeBasedToken as tbt
from httpDisplacer import httpDisplace
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from asyncThreads import async_thread




logging.basicConfig(level=logging.DEBUG)

class Client:
    def __init__(self, host, port, primary, special):
        self.server = None
        self.host = host
        self.port = port
        self.hello = None
        self.__running = True
        self.active = []
        self.config = {}
        self.threads = []
        self.session = PromptSession()
        self.__async_threads = []
        self.__recieved_goodbye = False
        
        self.TBT = tbt.TimeBasedToken(primary, special)

    def load_config(self, config_file_path: str):
        with open(config_file_path, 'r') as file:
            self.config = json.load(file)

    @validatetyping
    def create_hello(self,ports: list):
        self.hello = f"RTS_HELLO ports={str(ports)}"
        logging.debug(f"Hello message: {self.hello}")

    async def listen_to_terminal(self):
        print("terminal enabled")
        commands = ["exit", "blockIP", "pardonIP", "halt", "continue", "closePort", "openPort"]
        help_message = (
            "Not a recognized command\n"
            "exit - close remote session safely\n"
            "blockIP <ip> - prevent an IP from being tunneled\n"
            "pardonIP <ip> - remove an IP from the blocklist\n"
            "halt - pause traffic tunneling\n"
            "continue - continue traffic tunneling\n"
            "openPort <port> - open a port during runtime\n"
            "closePort <port> - close a port during runtime"
        )



        while self.__running:
            with patch_stdout():
                try:
                    uinput = await self.session.prompt_async("> ")
                except KeyboardInterrupt:
                    self.shutdown()
                    break
            
            if uinput not in commands:
                print(help_message)
                continue
            if uinput == "exit":
                self.server.send(b"RTS_GODBYE")
                logging.debug("Sent RTS_GODBYE")
                self.shutdown()
                break

    def connect_to_server(self):
        thread = async_thread(target=self.listen_to_terminal)
        logging.debug(f"Started terminal listener at {thread}")
        self.__async_threads.append(thread)


        if not self.hello:
            raise AttributeError("Missing hello message. Call create_hello() first.")

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        client.bind(('0.0.0.0', self.port))
        self.server = client
        self.active.append(client)
        self.TBT.regenerate()
        client.connect((self.host, self.port))

        self.hello = self.TBT.encrypt(self.hello)
        client.send(self.hello.encode())

        try:
            response = client.recv(4096).decode()
            response = self.TBT.decrypt(response)
        except socket.timeout:
            logging.warning("Connection Timeout")
            return
        logging.debug(response)

        if response.startswith("RTS_ERROR "):
            logging.error(response[10:])
            return

        if not response.startswith("RTS_HELLO"):
            raise ValueError("Server did not respond with the expected RTS_HELLO message.")

        logging.info("Connected")
        while self.__running:
            client.settimeout(None)
            try:
                response = client.recv(4096).decode()
                if not response:
                    continue
                
                response = self.TBT.decrypt(response)
                logging.info(f"\n\n<<<INBOUND\n{response}")
        
                if response == "RTS_GOODBYE":
                    self.__recieved_goodbye = True
                    logging.info("Server closed connection")
                    self.shutdown()
                    break
                
                if response.startswith("RTS_PUSH "):
                    self.handle_push_response(response)
            except (ConnectionResetError, ConnectionAbortedError):
                logging.warning("Connection lost")
                self.shutdown()
                break

    def handle_push_response(self, response):
        re_port = r'RTS_PUSH (\d+) ID'
        re_id = r'ID (\d+) RECIEVED'

        port_match = re.search(re_port, response)
        id_match = re.search(re_id, response)

        if port_match and id_match:
            port = port_match.group(1)
            ident = id_match.group(1)
            kill = 23 + len(port) + len(ident)
            data = response[kill:]

            logging.debug(f"{port},{ident},{data}")

            typ = "unidentified"
            ip = None

            if data.startswith(("GET", "POST", "PUT", "DELETE")):
                typ = "http"
                ip, port = httpDisplace(data, self.config)

            logging.debug(port)
            thread = threading.Thread(target=self.internal_request, args=(typ, port, ident, data, ip))
            self.threads.append(thread)
            thread.daemon = True
            thread.start()
            thread.join()
            try:
                self.threads.remove(thread)
            except ValueError:
                pass

    def internal_request(self, typ, port, ident, data, ip):
        logging.debug("Trying to push")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, int(port)))
            s.settimeout(5.0)
            s.send(data.encode())

            time.sleep(1)
            logging.debug("Sent data and waiting for response")
            resp = s.recv(4096)
        except socket.timeout:
            logging.warning("Socket timeout")
            issue = self.TBT.encrypt(f"RTS_TIMEOUT {ident}")
            self.server.send(issue.encode())
            return
        except socket.error as err:
            logging.error(err)
            issue = self.TBT.encrypt(f"RTS_ERROR Node to Service error.")
            self.server.send(issue.encode())
            return
        except Exception as e:
            logging.error(e)
            issue = self.TBT.encrypt(f"RTS_ERROR Miscellaneous error.")
            self.server.send(issue.encode())
            return
        finally:
            s.close()

        send_msg = f"RTS_RESPONSE {ident} RETURNED {resp.decode()}"
        logging.info(f"\n>>> OUTBOUND\n{send_msg}\n\n")
        send_msg = self.TBT.encrypt(send_msg)
        self.server.sendall(send_msg.encode())

        if typ == "http":
            exit_msg = self.TBT.encrypt(f"RTS_END {ident}")
            self.server.send(exit_msg.encode())

    def shutdown(self):
        try:
            if not self.__recieved_goodbye:
                goodbye = self.TBT.encrypt("RTS_GOODBYE")
                self.server.send(goodbye.encode())
            for a in self.active:
                a.close()
            self.__running = False
            for async_thread in self.__async_threads:
                async_thread.close()
            for thread in self.threads:
                logging.debug(f"Stopping thread {thread}")
                thread.join()
                try:
                    self.threads.remove(thread)
                except ValueError:
                    pass
        except Exception as e:
            logging.error(e)
        finally:
            sys.exit(0)
