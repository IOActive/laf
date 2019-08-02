# LoRaWAN Security Framework - tcpProxy
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import socket, select, time ,sys, argparse
from utils.Fuzzer import fuzz


def parse_args():
    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This TCP proxy is mainly intended to be placed between the network server and a MQTT brokers. It also offers the posibility to fuzz data')

    requiredGroup = parser.add_argument_group('Required arguments')
    requiredGroup.add_argument('--lcl-port',
                      help='The local port to listen, eg. --lcl-port=623.',
                      type=int)                
    requiredGroup.add_argument('--dst-ip',
                      help='Destination host ip, eg. --dst-ip=192.168.3.101.')
    requiredGroup.add_argument('--dst-port',
                      help='Destination host port, eg. --dst-port=623.',
                      type=int)
    
    parser.add_argument("--fuzz-in",
                      nargs='+',
                      help='Fuzz data sent to dst-port in the given modes (see fuzzing modes in utils/fuzzer.py)',
                      type=int,
                      default=None)        

    return parser.parse_args()


# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print(e)
            return False

class TheServer:
    input_list = []
    channel = {}

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        if forward:
            print (clientaddr, "has connected")
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print ("Can't establish connection with remote server.",)
            print ("Closing connection with client side", clientaddr)
            clientsock.close()

    def on_close(self):
        print (self.s.getpeername(), "has disconnected")
        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        data = fuzz(data,fuzzInMode)
        print ('%r'%(data))
        self.channel[self.s].send(data)

if __name__ == '__main__':
        options = parse_args()

        localPort = int(options.lcl_port)
        remoteHost = options.dst_ip
        remotePort = int(options.dst_port)
        global fuzzInMode
        fuzzInMode = options.fuzz_in

        global forward_to
        forward_to = (remoteHost, remotePort)

        server = TheServer('', localPort)

        try:
            server.main_loop()
        except KeyboardInterrupt:
            print ("Stopping server")
sys.exit(1)
