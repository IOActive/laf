# LoRaWAN Security Framework - udpProxy
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import sys, socket, logging, threading, re, argparse
from utils.Fuzzer import fuzz
import utils.FileLogger as fileLoggin
import lorawanwrapper.LorawanWrapper  as LorawanWrapper

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

# Add a lock to the s socket to avoid the concurrent use
sSocketLock = threading.Lock()

class Client:
    def __init__(self, address, socket):
        self.address = address
        self.socket = socket
        self.socketLock = threading.Lock()

knownClients = list()


def parse_args():
    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This UDP proxy is mainly intended to be placed between a series gateways (packet_forwarders) and a network server or gateway bridge depending on the infraestructure being evaluated. It also offers the posibility to fuzz data in the desired direction (uplink or downlink)')

    requiredGroup = parser.add_argument_group('Required arguments')
    requiredGroup.add_argument('--port',
                                help='The local port to listen, eg. --port 623.',
                                required = True,
                                type=int)                
    requiredGroup.add_argument('--dst-ip',
                                required = True,
                                help='Destination host ip, eg. --dst-ip 192.168.3.101.')
    requiredGroup.add_argument('--dst-port',
                                required = True,
                                help='Destination host port, eg. --dst-port 623.',
                                type=int)
    parser.add_argument('--collector-port',
                        help='Packet forwarder data collector port, eg. --collector-port 1701. See auditing/datacollectors/PacketForwarderCollector.py',
                        type=int,
                        default=None)
    parser.add_argument('--collector-ip',
                        help='Packet forwarder data collector ip. Default is localhost. eg. --collector-ip 192.168.1.1. See auditing/datacollectors/PacketForwarderCollector.py',
                        default='')
    parser.add_argument("--fuzz-in",
                      nargs='+',
                      help='Fuzz data sent to dst-port in the given modes (see fuzzing modes in utils/fuzzer.py), eg. --fuzz-in 1 2 ...',
                      type=int,
                      default=None)        
    parser.add_argument("--fuzz-out", 
                      nargs='+',
                      help='Fuzz data sent to (source) port in the given modes (see fuzzing modes in utils/fuzzer.py), eg. --fuzz-out 1 2 ...',
                      type=int,
                      default=None)        
    parser.add_argument("-k", "--key",
                        help= 'Enter a device AppSKey (in hex format, a total of 32 characters / 16 bytes) to decrypt its FRMPayload and print it in plain text. You can also enter the AppKey if you wish to decrypt a given Join Accept. eg. 00112233445566778899AABBCCDDEEFF',
                        default=None)
    parser.add_argument("-p", "--path",
                        help= 'Filepath where to save the data. If not given, data will not be saved.',
                        default=None)
    parser.add_argument("--no-log",
                        help= 'Do not print UDP packages into console',
                        action= "store_true",
                        default= False)
    parser.add_argument("--no-parse",
                        help = "Do not parse PHYPayload. If this option is selected, Golang librarys from /lorawanwrapper/ won't be imported (golang libs compiling is not required)",
                        action = "store_true",
                        default = False)

    return parser.parse_args()

def setConsoleOptions():
    global fuzzInMode
    fuzzInMode = options.fuzz_in
    global fuzzOutMode
    fuzzOutMode = options.fuzz_out
    global key
    key = options.key
    
    global logIntoFile
    if options.path is not None:
        logIntoFile = True
        global path
        path=options.path
    else:
        logIntoFile = False
    
    global logIntoConsole
    logIntoConsole = not options.no_log
    global parsePHYPayload
    parsePHYPayload = not options.no_parse

    global collector_address
    if options.collector_port:
        collector_address = (options.collector_ip, options.collector_port)  
    elif options.collector_ip != '':
        print('You must provide the data collector port.')
    else:
        collector_address=None

def fail(reason):
	sys.stderr.write(reason + '\n')
	sys.exit(1)

def getKnownClient(address):
    for client in knownClients:
        if client.address == address:
            return client
    return None

def closeSockets():
    for client in knownClients:
        client.socket.close()

def formatData(data):
    result = ""
    
    if data:
        search = re.search('(.*)"data":"(.*?)"(.*)', data.decode('utf-8', 'backslashreplace'))
        if search: 
            global key
            phyPayload = LorawanWrapper.printPHYPayload(search.group(2), key)
            result = "\nParsed data: " + phyPayload
    
    return result

def printDataFrame(original_data, source_address, input_address, dest_address, output_port):    
    if logIntoConsole:
        if parsePHYPayload:
            logger.debug('UDP packet from {0} on {1} forwarding to {2} local port {3}:\n{4!r}{5}\n'.format(source_address,input_address, dest_address, output_port, original_data, formatData(original_data)))
        else:
            logger.debug('UDP packet from {0} on {1} forwarding to {2} local port {3}:\n{4!r}'.format(source_address,input_address, dest_address, output_port, original_data))
    
    if logIntoFile:
        fileLoggin.save(original_data,None)   

def recvThread(client): 
    print("This is the thread for "+ str(client.address))
    while True:
        
        client.socket.settimeout(0.01)
        
        # Acquiring receive lock in thread
        client.socketLock.acquire()

        try:
            #receive the data with the socket which previously forwarded 
            data, source_address = client.socket.recvfrom(65565)
            
        except socket.timeout as exc:
            # Timed out receive socket in thread
            client.socketLock.release()
            # Receive lock released in thread 
            continue
        
        
        client.socketLock.release()
        # Receive lock released in thread

        if not data:
            logger.error('an error ocurred')
            break    
        
        # Fuzz returns the string is fuzzOutMode is None
        data = fuzz(data,fuzzOutMode)

        # Acquiring send lock in thread
        sSocketLock.acquire()
        
        printDataFrame(data,source_address, client.socket.getsockname(), client.address, s.getsockname()[1])
        # send the data from the socket that formerly received th datagram from the gateway
        s.sendto(data,client.address)

        global collector_address
        if collector_address:
            s.sendto(data,collector_address)
        
        
        sSocketLock.release()        
        # Send lock released in thread
     

def server(localPort,remoteHost, remotePort):  

    global collector_address

    try:
        localPort = int(localPort)
    except:
        fail('Invalid port number: ' + str(localPort))


    try:
        remotePort = int(remotePort)
    except:
        fail('Invalid port number: ' + str(remotePort))
        

    try:
        # This socket will be used by the server to receive data and by the threads to send the remote back to source
        global s        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', localPort))
    except:
        fail('Failed to bind on port ' + str(localPort))
    
    destServer = (remoteHost, remotePort)
    
    print('All set.\n')
    
    while True:
        s.settimeout(0.01)
        
        # Acquiring receive lock in main thread
        sSocketLock.acquire()
     
        try:
            # Receive data from source
            data, source_address = s.recvfrom(65565)
        except socket.timeout as exc:
            # Timed out receive socket in main thread
            sSocketLock.release()
            # Receive lock released in main thread
            continue

        sSocketLock.release()
        # Receive lock released in main thread

        if not data:
            logger.error('an error ocurred')
            break    
        
        # Depending on the source address, a Client object is retrieved
        knownClient = None
        knownClient = getKnownClient(source_address)
        
        # Fuzz returns the string is fuzzInMode is None
        data = fuzz(data,fuzzInMode)
        
        # Forward the data if the client is known, using a socket previously created
        if knownClient is not None:
            print ("Client already registered in port: " + str(knownClient.address[1]) + " Clients list lenght: " + str(len(knownClients))) 

            # Acquiring send lock in main thread
            knownClient.socketLock.acquire()
            
            printDataFrame(data, source_address,s.getsockname(), destServer, knownClient.socket.getsockname()[1])
            
        
            knownClient.socket.sendto(data,destServer)
            
            if collector_address:
                knownClient.socket.sendto(data,collector_address)

            knownClient.socketLock.release()
            # Send lock released in main thread
        
        # Else, create a new socket, save client+socket, forward the data and start a listening proxy
        else:
            newSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Choose a random socket, with param 0
            newSocket.bind(('',0))

            print ("Creating a new client")
            newClient = Client(source_address, newSocket)
            knownClients.append(newClient)

            # Acquiring send lock in main thread
            newClient.socketLock.acquire()
            printDataFrame(data, source_address, s.getsockname(), destServer, newSocket.getsockname()[1])
            

            newSocket.sendto(data,destServer)
           
            if collector_address:
                newSocket.sendto(data,collector_address)

            newClient.socketLock.release()
            # Send lock released in main thread

            #Create the proxy listener in a thread
            listener=threading.Thread(target=recvThread,args = (newClient,))
            listener.daemon = True
            listener.start()

def collectData(lclPort, destIp, destPort, path):
    global logIntoConsole
    logIntoConsole = True

    global logIntoFile
    logIntoFile = True

    fileLoggin.init(path)

    try:
        server(lclPort, destIp, destPort)

    except KeyboardInterrupt:
        print("Exiting the proxy")
        
        #close sockets
        s.close()
        closeSockets()

        fileLoggin.close()

        exit(0)


if __name__ == '__main__':
    global options
    options = parse_args()
    setConsoleOptions()
    
    if logIntoFile:
        fileLoggin.init(path)

    try:
        server(options.port,options.dst_ip,options.dst_port)

    except KeyboardInterrupt:
        print("Exiting the proxy")
        #close sockets
        s.close()
        closeSockets()

        if logIntoFile is True:
            fileLoggin.close()

        exit(0)

        