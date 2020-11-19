# LoRaWAN Security Framework - udpSender
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import socket, logging, re, argparse, ast, sys
from tools.utils import Fuzzer, DevAddrChanger, MicGenerator, FCntChanger
import lorawanwrapper.LorawanWrapper as LorawanWrapper

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

def fail(reason):
	sys.stderr.write(reason + '\n')
	sys.exit(1)

def parse_args():
    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This tool is intended to send uplink packets (to the network server or gatewayBridge, depending on the infrastructure) or downlink packets (to the packet-forwarder). Optionally, packets can be fuzzed and a valid MIC can be calculated.')
    requiredGroup = parser.add_argument_group('Required arguments')
    requiredGroup.add_argument('--dst-ip',
                                required = True,
                                help='Destination ip, eg. --dst-ip 192.168.3.101.')
    requiredGroup.add_argument('--dst-port',
                                required = True,
                                help='Destination port, eg. --dst-port 623.',
                                type=int)     
    requiredGroup.add_argument('--data',
                                required = True,
                                help=r"""UDP packet. It can also be added more packets in "data" array at the end of this script. The packet must be a byte string (you will have to escape double quotes). ***EXAMPLE*** with the packet_forwarder format: --data "b'\x02\xe67\x00\xb8\'\xeb\xff\xfez\x80\xdb{\"rxpk\":[{\"tmst\":2749728315,\"chan\":0,\"rfch\":0,\"freq\":902.300000,\"stat\":1,\"modu\":\"LORA\",\"datr\":\"SF7BW125\",\"codr\":\"4/5\",\"lsnr\":9.5,\"rssi\":-76,\"size\":23,\"data\":\"AMQAAAAAhQAAAgAAAAAAAACH9PRMJi4=\"}]}'"  ***EXAMPLE*** using the gatevice [GV] format sending in inmediate mode, in BW125 and freq 902.3 is "b'{\"tx_mode\": 0, \"freq\": 902.3, \"rfch\": 0, \"modu\": 16, \"datarate\": 16, \"bandwidth\":3, \"codr\": 1, \"ipol\":false, \"size\": 24, \"data\": \"QOOL8AGA6AMCnudJqz3syCkeooCvqbSn\", \"class\": 2}'" """)
    parser.add_argument('--lcl-port',
                        help='Source port, eg. --lcl-port=623.',
                        default = 0,
                        type=int)
    parser.add_argument("--timeout", 
                        help='Time in seconds between every packet sent. Default is 1s. In this time, the sender will listen for replies.',
                        type=float,
                        default=1)  
    parser.add_argument("--repeat", 
                        help='Send message/s multiple times',
                        action= "store_true",
                        default=False) 
    parser.add_argument("--fuzz-out", 
                        nargs='+',
                        help='Fuzz data sent to dest port (see fuzzing modes in utils/fuzzer.py), eg.  --fuzz-out 1 2.',
                        type=int,
                        default=None)    
    parser.add_argument("--key",
                        help= 'Enter the key (in hex format, a total of 32 characters / 16 bytes) to sign packets (calculate and add a new MIC). Note that for JoinRequests it must be the AppKey, and the NwkSKey for Data packets. This cannot be validated beforehand by this program. eg. 00112233445566778899AABBCCDDEEFF',
                        default=None)  
    parser.add_argument("-a", "--devaddr",
                        help= "DeviceAddress to impersonate, given in hex format (8 characters total), eg. AABB0011.",
                        default = None)
    parser.add_argument("--fcnt",
                        help= "The frame counter to be set in the given data packet. This wouldn't work in a JoinRequest/JoinAccept since this packets don't have a fCnt",
                        type=int,
                        default = None)


    return parser.parse_args()

def formatData(data):
    result = ""
    
    if data is None:
        return result
    else:
        search = re.search('(.*)"data":"(.*?)"(.*)', data.decode('utf-8', 'backslashreplace'))
        if search is not None: #means that a PHYPayload was received
            phyPayload = LorawanWrapper.printPHYPayload(search.group(2), None)
            result += "\nParsed data: " + phyPayload

        return result        

def sender(data, fuzz_out_mode, key, dev_address, timeout, new_counter, local_port, remote_ip, remote_port):

    try:
        remote_port = int(remote_port)
    except:
        fail('Invalid port number: ' + str(remote_port))
        
    try:   
        global send_socket
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_socket.bind(('', local_port))
    except:
        fail('Failed to bind on port ' + str(local_port))
    
    remote_host = (remote_ip, remote_port)

    print('\n'+'Sent to: '+ str(remote_host))
    for message in data:

        # If given, this will change the address of the packet
        message = DevAddrChanger.changeAddress(message, dev_address)

        # If given any fuzz mode, this will return the fuzzed packet. Otherwise, it does nothing
        message = Fuzzer.fuzz(message,fuzz_out_mode)

        # If given a FCnt, replace in the packet
        message = FCntChanger.changeFCnt(message, new_counter)

        # If key given, this will generate a new valid MIC 
        message = MicGenerator.generate_mic(message, key)

        send_socket.sendto(message,remote_host)
        logger.debug('{0!r} {1}'.format(message, formatData(message)))
        receiver(send_socket, timeout)

def receiver(send_socket, timeout):  

    send_socket.settimeout(timeout) 

    try:
        data, source_address = send_socket.recvfrom(65565)
        if not data:
            logger.error('an error ocurred')
        else:
            logger.debug('Received UDP. Source {0}. Local port {1}:\n{2!r}{3}'.format(source_address, send_socket.getsockname()[1], data, formatData(data)))
    except socket.timeout as exc:
        print("Timed out receive window")
    finally:
        send_socket.close()

def udp_sender(data, repeat, fuzz_out_mode, key, dev_address, timeout, new_counter, local_port, remote_ip, remote_port):

    while True: 
        try:
            sender(data, fuzz_out_mode, key, dev_address, timeout, new_counter, local_port, remote_ip, remote_port)

            if not repeat:
                break
            
        except KeyboardInterrupt:
            print("Exit")
            exit(0)

if __name__ == '__main__':
    options = parse_args()

    fuzz_out_mode = options.fuzz_out
    key = options.key
    dev_address = options.devaddr
    timeout = options.timeout
    repeat = options.repeat
    new_counter= options.fcnt
    
    local_port = options.lcl_port
    remote_ip = options.dst_ip
    remote_port = options.dst_port

    if new_counter is not None or dev_address is not None:
        if key is None:
            print("Warning! Since you are modifying the packet, you should provide a network session key to sign it.")

    data = [
            # Here it can be added as many UDP packets as you want. They must be comma separated and it is recommended to add them between triple quotes.
            ast.literal_eval(options.data)
        ]

    udp_sender(data, repeat, fuzz_out_mode, key, dev_address, timeout, new_counter, local_port, remote_ip, remote_port)
        
    
    