import socket
import time
import threading
import re
import sys
import logging
import json
from ExtraDecorators import validatetyping
import ExtraUtils.asyncTokens as astok
logging.basicConfig(level=logging.DEBUG)

class Client:
    def __init__(self, host, port):
        self.server = None
        self.host = host
        self.port = port
        self.hello = None
        self.active = []
        self.config = {}
        self.key, self.pub = astok.gen_keypair()
        self.other_pub = None

    def load_config(self, configFilePath:str):
        with open(configFilePath, 'r') as file:
            self.config = json.load(file)
        

    @validatetyping
    def create_hello(self,token:str, ports:list):
        #self.hello = f"RTS_HELLO pub={astok.serial(self.pub)};;ports={str(ports)}"
        self.hello = f"RTS_HELLO pub={None};;token={token};;ports={str(ports)}"
        logging.debug(f"Hello message: {self.hello}")
    
    def listen_to_terminal(self):
        print("terminal enabled")
        while True:
            uinput = input("")
            print(uinput)
            if uinput not in ["exit", "blockIP", "pardonIP", "halt", "continue","closePort","openPort"]:
                print("Not a recognized command\nexit - close remote sesstin safely\nblockIP <ip> - prevent an ip from being tunneled\npardonIP <ip> - remove an ip from the blocklist\nhalt - pause traffic tunneling\ncontinue - continue traffic tunneling\nopenPort <port> - open a port during runntime\nclosePort <port> - close a port during runntime")
            
            if uinput == "exit":
                self.server.send(b"RTS_GODBYE")
                logging.debug("Sent RTS_GODBYE")
                self.shutdown()
                sys.exit(1)
            pass

    def connect_to_server(self):
        threading.Thread(target=self.listen_to_terminal).start()

        if not self.hello:
            raise AttributeError("Missing hello message .create_hello()")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        client.bind(('0.0.0.0', self.port))
        self.server = client
        self.active.append(client)
        client.connect((self.host, self.port))
        client.send(self.hello.encode())
        try:
            response = client.recv(4096).decode()
            #response = astok.decrypt(response, self.key)
        except socket.timeout:
            logging.warning("Connection Timeout")
            return
        logging.debug(response)
        if response.startswith("RTS_ERROR "):
            logging.error(response[10:])
            return
        if response != "RTS_HELLO":
            raise ValueError("Server did not Respond with the expected RTS_HELLO message.")
        re_pub = r"pub=(.*);;"
        pub = re.search(re_pub, response)
        #if pub:
        #    self.other_pub = astok.load(pub.group(1))
        logging.info("Connected")
        while True:
            client.settimeout(None)
            response = client.recv(4096).decode()
            #response = astok.decrypt(response, self.key)

            if len(response) == 0:
                continue
            logging.info(f"\n\n<<<INBOUND\n{response}")
            if response.startswith("RTS_PUSH "):
                re_port = r'RTS_PUSH (\d+) ID'
                re_id = r'ID (\d+) RECIEVED'
                prt = re.search(re_port, response)
                if prt:
                    port = prt.group(1)
                i = re.search(re_id,response)
                if i:
                    ident = i.group(1)
                kill = 23 + len(port) + len(ident)
                data = response[kill:]
                logging.debug(port,ident,data)
                if data.startswith(("GET","POST","PUT","DELETE")):
                    re_host = r'Host: (.*)\r\n'
                    horst = re.search(re_host, data)
                    if horst:
                        logging.debug(f"Host: {horst.group(1)}")
                        if self.config.get("httpPortDisplace"):
                            for hport in self.config["httpPortDisplace"]:
                                if horst.group(1) == hport["host"]:
                                    port = hport["port"]
                                    break

                thread = threading.Thread(target=self.internal_request, args=(port,ident,data,))
                thread.daemon = True
                thread.start()

    def internal_request(self,port,ident, data):
        logging.debug("trying to push")
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("localhost", int(port)))
        s.settimeout(5.0)
        s.send(data.encode())
        resp = None
        try:
            time.sleep(1)
            logging.debug("sended and waiting for response")
            resp = s.recv(4096)
        except socket.timeout:
            logging.warning("socket timeout")
            #self.server.send(astok.encrypt(f"RTS_TIMEOUT {ident}", self.other_pub))
            self.server.send(f"RTS_TIMEOUT {ident}".encode())
    
            return
        except socket.error as err:
            logging.error(err)
            self.server.send(astok.encrypt(f"RTS_ERROR Node to Service error.", self.other_pub))
            return
        send_msg = f"RTS_RESPONSE {ident} RETURNED {resp.decode()}".encode()
        logging.info(f"\n>>> OUTBOUND\n{send_msg}\n\n")
        #send_msg = astok.encrypt(send_msg, self.other_pub)
        self.server.sendall(send_msg)



    
    def shutdown(self):
        for a in self.active:
            a.close()


# Beispielverwendung
#try:
#    cli = Client('remote.randomtime.tv', 8883)
#    cli.create_hello(token="token",ports=["443"])
#    cli.load_config("/home/randomtime/server/client.json")
#    cli.connect_to_server()
#except KeyboardInterrupt:
#    logging.info("Shutting down")
#    cli.shutdown()
#except Exception as e:
#    logging.critical(e)
#    cli.shutdown()