from ExtraUtils.timeBasedToken import TimeBasedToken
import ExtraUtils.asyncTokens as astk
import socket
import threading
import ssl
import asyncio
from ExtraUtils.asyncThreads import async_thread
from time import sleep
import re

class Node:
    def __init__(self, primary_token:str, special_token:str):
        self.__TBT = TimeBasedToken(primary_token, special_token)
        self.__type:str = None
        self.__port:int = None
        self.__host:str = None
        self.__master_connection = None
        self.__slave_connections = {}
        self.__clients = {}
        self.__bound = {"tcp":None, "udp":None}
        self.__ssl = None
        self.__threads = []
        self.__config:dict = {}
        self.__trust_level = None
        self.__async_threads = []
        self.__self_key = None
        self.__self_pem = None
        self.__udp_sockets = []
        self.__tcp_sockets = []
        self.__node_name_map = {}
        

    #internal
    def as_client_server(self, target_host:str, target_port:int,config:dict=None):
        print("Client server setup")
        if config:
            self.__config = config
        self.__host = target_host
        self.__port = target_port
        self.__type = "manager"

    #internal desktop
    def as_client_reader(self, manager_host:str, manager_port:int, node_name:str,config:dict=None):
        print("Client setup")
        if config:
            self.__config = config
        self.__port = manager_port
        self.__host = manager_host
        self.__type = "client"

    #external
    def as_server(self, ssl_cert:str, ssl_key:str, port:int, node_name:str,config:dict=None):
        print("Server setup")
        if config:
            self.__config = config
        self.__port = port
        self.__ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.__ssl.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
        self.__type = "server"

    def connectivity_trust_level(self,level:int=1):
        assert level in range(0,4), "Invalid trust level"
        self.__trust_level = level
        if not self.__config.get("self"):
            self.__trust_level = 3
            print("⚠️ Config file does not contain configs about 'self', Falling back to insecure 'all Trusted' mode (3) ⚠️")
        else:
            if not self.__config["self"].get("key") or not self.__config["self"].get("pem"):
                self.__trust_level = 3
                print("⚠️ Config file is lacking the 'key' and 'pem' filepaths. Falling back to insecure 'all Trusted' mode (3) ⚠️")
                return
            #try:
            with open(self.__config["self"]["key"], 'r') as file:
                key_content = file.read()
                print("sepf pub:", key_content)
                self.__self_key = astk.load(key_content)
            with open(self.__config["self"]["pem"], 'r') as file:
                pem_content = file.read()
            print("sepf pem:", pem_content)
            self.__self_pem = astk.load_private(pem_content)
            #except Exception as e:
            #    print("⚠️ An error occurred while trying to load the key and pem files. Falling back to insecure 'all Trusted' mode (3) ⚠️")
            #    print(e)
            #    self.__trust_level = 3

    def sign(self, message:str):
        if self.__trust_level <= 2:
            return astk.sign(message, self.__self_pem)
        return message
    
    def verify(self, message:str,expected:str, pub_key):
        if self.__trust_level <= 2:
            return astk.verify(message,expected, pub_key)
        return True
    
    def dec(self, message:str):
        if self.__trust_level <= 1:
            if isinstance(message, str):
                message = message.encode()
            return astk.decrypt(message, self.__self_pem)
        return message
    
    def enc(self, message:str, pub_key):
        if self.__trust_level <= 1: 
            return astk.encrypt(message, pub_key)
        return message
    
            
    def port_config(self):
        print("Configuring ports")
        
        for port in self.__config:
            if port in ["self","nodes","host"]:
                continue
            if self.__type == "server":
                #setup udp
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.bind(('0.0.0.0', int(port)))
                self.__udp_sockets.append(udp_socket)
                thr = threading.Thread(target=self.__udp_listen, args=(port,))
                thr.deamon = True
                thr.start()
                self.__threads.append(thr)

                #setup tcp
                try:
                    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tcp_socket.bind(('0.0.0.0', int(port)))
                    tcp_socket.listen(1)
                    self.__tcp_sockets.append(tcp_socket)
                    while True:
                        client, addr = tcp_socket.accept()
                        if not client or not addr:
                            continue
                        ip, por = addr
                        self.__clients[ip+":"+por] = client
                        athread = threading.Thread(target=self.__listening, args=(client,port,))
                        athread.deamon = True
                        athread.start()
                        self.__threads.append(athread)
                except Exception as e: 
                    print(f"TCP ERROR: an error occurred while trying to bind to port {port} \n {e}")
      
    def setup_sequence(self):
        print("Setting up connection")
        assert self.__type, "Node not setup: as_manager, as_client, or as_server"
        assert self.__trust_level in range(0,4), "Trust level not set use connectivity_trust_level(<level>)"

        #tcp
        tcp_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_node.bind(('0.0.0.0', self.__port))
        self.__bound["tcp"] = tcp_node

        #udp
        udp_node = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_node.bind(('0.0.0.0', self.__port))
        self.__bound["udp"] = udp_node
        
        if self.__type == "server":
            print("Setting up server Listening...")
            tcp_node.listen(1)

            athread = threading.Thread(target=self.port_config)
            athread.deamon = True
            athread.start()
            self.__async_threads.append(athread)


        if self.__type == "manager":
            assert self.__host and self.__port, "tcp_node not setup: as_client_reader, as_client_server, or as_server"
            tcp_node.connect((self.__host, self.__port))
            self.__master_connection = tcp_node
            udp_node.sendto(b"RTS_PING", (self.__host, self.__port))
            
        thread = threading.Thread(target=self.__udp_listen, args=(self.__port,))
        thread.deamon = True
        thread.start()
        self.__threads.append(thread)
        asyncio.run(self.listening_startup())   

    async def listening_startup(self):

        node:socket.socket = self.__bound["tcp"]
        if self.__type == "manager":
            print("Client listening startup")

            #login and verify sequence
            self.__master_connection.send(f"RTS_WHOAMI {self.__config['self']['whoami']}".encode())
            data = self.__master_connection.recv(512)	
            print("Recieved", data)
 

            #get the host public key
            assert self.__config.get("host"), '"host" not found in config file'
            if self.__trust_level <= 1:
                host_pub = None
                with open(self.__config["host"]["key"], 'r') as file:
                    host_content = file.read()
                    print(host_content)
                    host_pub = astk.load(host_content)

                data = self.verify(data, "RTS_HELLO", host_pub)
                print("Decrypted data", data)
            #verify the message
            if not data:
                self.__master_connection.send(b"RTS_ERROR Verification failed.")
                self.__master_connection.close()
                return
            
            sig = self.sign("RTS_HELLO")

            self.__master_connection.send(sig)
            #connection verified
            
            
            print("Should start listening now...")
            asthread = threading.Thread(target=self.__listening, args=(self.__master_connection,self.__port))
            asthread.deamon = True
            asthread.start()
            self.__async_threads.append(asthread)
            
        if self.__type == "server":
            print("Server listening startup")
            while True:
                client, addr = node.accept()
                print("Client accepted", addr)

                #login and verify sequence
                if not client or not addr:
                    continue
                dat = client.recv(512).decode()
                print("Recieved", dat)

                if not dat.startswith("RTS_WHOAMI"):
                    print("Did not recieve RTS_WHOAMI\n", dat)
                    client.close()
                    continue
                name = dat[11:]
                print("Name", name)
                # file deepcode ignore AttributeLoadOnNone: this is fine
                if not self.__config.get("nodes").get(name) and self.__trust_level <= 2:
                    print("Node identification failed")
                    client.send(b"RTS_ERROR Node identification failed.")
                    client.close()
                    continue
                print("Node identified")
                
                if self.__trust_level <= 1: #v1.0
                    client_pub = None
                    with open(self.__config["nodes"][name]["key"], 'r') as file:
                        client_pub = astk.load(file.read())
                    sig = self.sign("RTS_HELLO")
                    print("Sending signature", sig)
                    client.send(sig)

                    # file deepcode ignore HandleUnicode: gets handled else where
                    verification_message = client.recv(2048)
                    print("Verification message", verification_message)
                    if verification_message.startswith(b"RTS_ERROR"):
                        print("Verification failed")
                        client.close()
                        continue

                    verification_message = self.verify(verification_message,"RTS_HELLO", client_pub) 
                    print("Verification message", verification_message)
                    if not verification_message:
                        print("Verification failed")
                        client.send(b"RTS_ERROR Verification failed.")
                        client.close()
                        continue
                    #connection verified
                    print("Connection verified")

                #asthread = threading.Thread(target=self.__listening, args=(client,self.__port, ip))
                #asthread.deamon = True
                #asthread.start()
                #self.__async_threads.append(asthread)

                
    def __udp_listen(self,port:int):
        print("UDP Listening " + str(port))
        memory = None
        node = self.__bound["udp"]
        while True:
            data, addr = node.recvfrom(1024)
            if not data:
                continue
            print(data)
            print(addr)
            if data == b"RTS_PING":
                if not memory:
                    memory = addr
                node.sendto(b"RTS_PONG", addr)
                continue
            if data == b"RTS_PONG":
                def send():
                    sleep(20)
                    node.sendto(b"RTS_PING", (self.__host, self.__port))
                thread = threading.Thread(target=send)
                thread.start()
                continue
            if memory:
                node.sendto(data, memory)
                continue


    def __listening(self,client, port:int, ip):
        print("Listening frattik")
        client.settimeout(None)
        while True:
            try:
                print("Reading")
                data = client.recv(4096)

                if not data:
                    continue
                if data.startswith(b"RTS_WHOAMI"):
                    pass

                if data.startswith(b"RTS_RESPONSE"):
                    pass

                if data.startswith(b"RTS_REQUEST"):
                    self.__rts_request(data)
                        
                if self.__config.get(port):
                    for recipient in self.__config[port]:
                        if not recipient.get("to_node") in self.__slave_connections:
                            continue
                        self.__slave_connections[recipient.get("to_node")].send(data)
                        continue
                    

                print(data)
            except Exception as e:
                print(e)
                continue

    def __tcp_request(self,port,ident,data,ip):
        print("Trying to push")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((ip, int(port)))
            s.settimeout(5.0)
            s.send(data.encode())

            sleep(1)
            print("Sent data and waiting for response")
            resp = s.recv(4096)
        except socket.timeout:
            print("Socket timeout")
            issue = f"RTS_TIMEOUT {ident}"
            self.server.send(issue.encode())
            return
        except socket.error as err:
            print(err)
            issue = f"RTS_ERROR Node to Service error."
            self.server.send(issue.encode())
            return
        except Exception as e:
            print(e)
            issue = f"RTS_ERROR Miscellaneous error."
            self.server.send(issue.encode())
            return
        finally:
            s.close()

        send_msg = f"RTS_RESPONSE {ident} DATA {resp.decode()}"
        print(f"\n>>> OUTBOUND\n{send_msg}\n\n")
        #send_msg = self.TBT.encrypt(send_msg)
        self.server.sendall(send_msg.encode())

    def __rts_request(self,data):
        data = data.decode()
        re_port = r'RTS_PUSH (\d+) ID'
        re_id = r'ID (\d+) DATA'
        port_match = re.search(re_port, data)
        id_match = re.search(re_id, data)
        if port_match and id_match:
            port = port_match.group(1)
            ident = id_match.group(1)
            kill = 23 + len(port) + len(ident)
            data = data[kill:]
            self.__tcp_request(port,ident,data,"localhost")



