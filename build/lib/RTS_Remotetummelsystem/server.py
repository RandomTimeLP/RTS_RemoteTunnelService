import socket
import ast
import threading
import re
import sys
import logging
import ssl
from scapy.all import Raw
from snowflake import Snowflake
from ExtraUtils import RateLimiter
import ExtraUtils.asyncTokens as asyncToken
logging.basicConfig(level=logging.DEBUG,filename="server.log",format="%(asctime)s - %(levelname)s - %(message)s")


class Server:
    def __init__(self, host, port, token,use_ssl=False, ssl_cert=None, ssl_key=None):
        self.node = None
        self.host = host
        self.port = port
        self.token = token
        self.blocked_ips = set()
        self.ports_in_q = set()
        self.active = []
        self.active_requests = 0
        self.ratelimit = RateLimiter(40,50,1,1)
        self.ssl_ports = [443,465,563,636,989,990,992,993,994,995,5061,8443,8531,9443,1194,1443,1443,18443,2443,4443,5443]
        self.prohibited_ports= [0,22,8888]

        
        self.key, self.pub = asyncToken.gen_keypair()
        self.other_pub = None
        self.use_ssl = use_ssl
        if self.use_ssl:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            #self.ssl_context.options &= ~ssl.OP_NO_SSLv3 & ~ssl.OP_NO_TLSv1 & ~ssl.OP_NO_TLSv1_1
            self.ssl_context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
        else:
            self.ssl_context = None
        


        
    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        self.active.append(server)
        server.listen(1)
        logging.info(f"Server listening on {self.host}:{self.port}")

        while True:
            cli, addr = server.accept()
            self.active.append(cli)

            if not cli:
                continue
            self.ratelimit.increment()
            if self.ratelimit.hit:
                cli.close()
            hello = cli.recv(512)
            ip, port = addr
            if self.node:
                cli.send(b"RTS_ERROR Connection occupied.")
                logging.error(f"Connection from {ip}:{port} denied: Occupied_Error")
                cli.close()
                continue
            if port != self.port:
                cli.send(f"RTS_ERROR Invalid connection port, expecting connection from port {self.port}".encode())
                logging.error(f"Connetion blocked, invalid Port using {ip}:{port}")
                cli.close()
                continue
            if not hello.startswith(b"RTS_HELLO "):
                cli.send("RTS_ERROR No RTS_HELLO message recieved.".encode())
                logging.error("Did not recieved RTS_HELLO")
                cli.close()
                continue
            hello = hello.decode()
            message_str = hello.replace("RTS_HELLO ", "")
            pairs = message_str.split(";;")

            hi = {}
            for pair in pairs:
                key, value = pair.split("=")
                if key in ["ports", "blocked"]:
                    value = ast.literal_eval(value)
                hi[key] = value
            print(hi)
            #if hi.get("pub"):
            #    self.other_pub = asyncToken.load(hi.get("pub"))

            self.node = cli
            self.ports_in_q = hi["ports"]
            logging.info(f"\nAccepted connection from: {ip}:{port}\n")
            print(self.other_pub)
            #hello_msg = asyncToken.encrypt(f"RTS_HELLO pub={asyncToken.serial(self.pub)};;",self.other_pub)
            hello_msg = f"RTS_HELLO pub=None;;"
            cli.send(hello_msg.encode())
            self.setup_ports()
            while True:
                cli.settimeout(None)
                try:
                    read = cli.recv(1024).decode()
                    #read = asyncToken.decrypt(read,self.key)
                except socket.error as ser:
                    logging.error(ser)
                    cli.close()
                    self.node = None
                if read.startswith("RTS_GOODBY"):
                    self.shutdown()
                    sys.exit(1)


    def setup_ports(self):
        if not self.ports_in_q:
            return
        for port in self.ports_in_q:
            if int(port) in self.prohibited_ports:
                self.node.send(f"RTS_WARNING Prohibited port {port}".encode())
                continue

            listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen.bind(("0.0.0.0", int(port)))
            self.active.append(listen)
            logging.info(f"\nPort {port} created.\n")
            listen.listen()
            threading.Thread(target=self.read_socket, args=(listen,port,)).start()
                                    
    def read_socket(self, port_sock:socket.socket, port):
        while True:
            con, add = port_sock.accept()
            if not con:
                continue

            with open("/root/remoteredirector/blockedIPS.frw","r") as f:
                for line in f.readlines():
                    if add[0] in line:
                        logging.debug(f"Blocked IP {add[0]} tried to connect.")
                        con.send(b"RTS_ERROR Access denied.")
                        con.close()
                        continue
            
            self.ratelimit.increment()
            if self.ratelimit.hit:
                con.close()
                continue
            
            con.settimeout(5.0)
            
            if int(port) in self.ssl_ports:
                try:
                    con = self.ssl_context.wrap_socket(con, server_side=True)
                    #self.node.send(asyncToken.encrypt(f"RTS_PORTREG {port} as SSL",self.other_pub).encode())
                    self.node.send(f"RTS_PORTREG {port} as SSL".encode())
                except ssl.SSLError as e:
                    logging.error(f"\n{add} caused an error: {e}\n")
                    #self.node.send(asyncToken.encrypt(f"RTS_PORTREG {port} as SSL FAILED",self.other_pub).encode())
                    self.node.send(f"RTS_PORTREG {port} as SSL FAILED".encode())
                    con.close()
                    continue

            try:
                data:bytes = con.recv(5120)
            except socket.timeout:
                logging.warning(f"\n{add} timedout.\n")
                continue
            except socket.error as e:
                logging.error(f"\n{add} caused an error: {e}\n")
                continue
            
            data = data.decode()
            pack = Raw(load=data)
            logging.info(f"\n{pack.summary}\n")

            snow = Snowflake().generate_id()
            send_msg = f"RTS_PUSH {port} ID {snow} RECIEVED {data}"
            #end_msg = asyncToken.encrypt(send_msg,self.other_pub)  
            # RTS_RESPONSE {id} RETURNED
            logging.info(f"\n>>>OUTGOING source {add}\n{send_msg}\n")
            self.node.settimeout(5.0)
            self.node.send(send_msg.encode())
            try:
                ret:bytes = self.node.recv(2048).decode()
                #ret = asyncToken.decrypt(ret,self.key)
            except socket.timeout:
                logging.warning("Return message timed out\n")
                con.close()
                continue
            except socket.error as err:
                logging.error(f"ServiceServer error:\n{err}\n")
                con.close()
                continue
            logging.info(f"\n<<<INCOMMING\n{ret}\n")
            if ret.startswith("RTS_TIMEOUT"):
                retid = ret[12:]
                logging.warning(f"Service Server reported RTS_TIMEOUT for message ID {retid}\n")
                con.close()
                continue
            # RTS_PUSH
            re_id = r'RTS_RESPONSE (\d+) RETURNED'
            i = re.search(re_id,ret)
            if i:
                ident = i.group(1)
            else:
                raise ValueError("no id")
            kill = 23+len(ident)
            ret:str = ret[kill:]
            logging.info(f"\n>>>OUTGOING\n{ret}\n")
            con.sendall(ret.encode())
    



    def shutdown(self):
        for a in self.active:
            logging.info(f"closing connection {a}")
            a.close()


# Beispielverwendung
#try:
serv = Server('0.0.0.0', 8883, "token",True,"/etc/letsencrypt/live/randomtime.tv/fullchain.pem","/etc/letsencrypt/live/randomtime.tv/privkey.pem")
serv.start_server()
#except KeyboardInterrupt:
#    logging.info("shuting down")
#    serv.shutdown()
#except Exception as e:
#    logging.critical(e)
#    serv.shutdown()