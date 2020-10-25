import UdpSender, sys, argparse

if __name__ == '__main__':

    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This tool is intended to send uplink packets (to the network server or gatewayBridge, depending on the infrastructure) or downlink packets (to the packet-forwarder). Optionally, packets can be fuzzed and a valid MIC can be calculated.')
    requiredGroup = parser.add_argument_group('Required arguments')
    parser.add_argument('--dst-ip',
                                help='Destination ip, eg. --dst-ip 192.168.3.101. Default: 127.0.0.1.',
                                default='127.0.0.1')
    requiredGroup.add_argument('--dst-port',
                                required = True,
                                help='Destination port, eg. --dst-port 623.',
                                type=int)     
    requiredGroup.add_argument('--data',
                                required = True,
                                help='LoRaWAN packet in Base64')
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

    option= parser.parse_args()

    data_to_send= list()

    data_len= int((len(option.data) * 3) / 4 - option.data.count('=', -2))

    gatevice_message= b'{\"tx_mode\": 0, \"freq\": 902.3, \"rfch\": 0, \"modu\": 16, \"datarate\": 16, \"bandwidth\":3, \"codr\": 1, \"ipol\":false, \"size\":'+ str(data_len).encode('utf-8') +b', \"data\":\"' + option.data.encode('utf-8') + b'\", \"class\": 2}' 
    data_to_send.append(gatevice_message)
    
    UdpSender.udp_sender(data_to_send, option.repeat, None, None, None, option.timeout, None, option.lcl_port, option.dst_ip, option.dst_port)