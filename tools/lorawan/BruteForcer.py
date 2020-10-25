# LoRaWAN Security Framework - BruteForcer.py
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import argparse, base64,sys
import lorawanwrapper.LorawanWrapper as LorawanWrapper

keys=list()

def bruteforce_accept_request(ja, jr, dont_generate_keys):
    global keys

    jr_result = LorawanWrapper.testAppKeysWithJoinRequest(keys, jr, dont_generate_keys)  

    if len(jr_result) > 0:
        
        # Convert valid keys into bytes
        valid_keys= list()
        for valid_key in jr_result.split():
            valid_keys.append(bytes(valid_key.upper(), encoding='utf-8'))

        ja_result = LorawanWrapper.testAppKeysWithJoinAccept(valid_keys, ja, dontGenerateKeys= True)

        if len(ja_result) > 0:
            print ("\n**** Key found: %s **** \n"%(ja_result.split()[0]))


def bruteforce_two_join_requests(jr1, jr2, dont_generate_keys):
    global keys

    jr_1_result = LorawanWrapper.testAppKeysWithJoinRequest(keys, jr1, dont_generate_keys)  

    if len(jr_1_result) > 0:
        
        # Convert valid keys into bytes
        valid_keys= list()
        for valid_key in jr_1_result.split():
            valid_keys.append(bytes(valid_key.upper(), encoding='utf-8'))

        jr_2_result = LorawanWrapper.testAppKeysWithJoinRequest(valid_keys, jr2, dontGenerateKeys= True)

        if len(jr_2_result) > 0:
            print ("\n**** Key found: %s **** \n"%(jr_2_result.split()[0]))

def bruteforce_two_join_accepts(ja1, ja2, dont_generate_keys):
    global keys
    
    ja1_result = LorawanWrapper.testAppKeysWithJoinAccept(keys, ja1, dont_generate_keys)  

    if len(ja1_result) > 0:
        
        # Convert valid keys into bytes
        valid_keys= list()
        for valid_key in jr_result.split():
            valid_keys.append(bytes(valid_key.upper(), encoding='utf-8'))

        ja_2_result = LorawanWrapper.testAppKeysWithJoinAccept(valid_keys, ja2, dontGenerateKeys= True)

        if len(ja_2_result) > 0:
            print ("\n**** Key found: %s **** \n"%(ja_2_result.split()[0]))

def validateKeys(first, second, keysPath, dont_generate_keys):
    global keys
    with open(keysPath) as f:
        for k in f:
            # Fetch keys in byte format. Needed by ctypes
            keys.append(bytes(k.rstrip().upper(), encoding='utf-8'))  
    
    first_decoded=base64.b64decode(first)
    first_m_type= first_decoded[0] & 0xE0

    second_decoded=base64.b64decode(second)
    second_m_type= second_decoded[0] & 0xE0

    if first_m_type == 0x00:
        if second_m_type == 0x00:
            bruteforce_two_join_requests(first, second, dont_generate_keys)
        elif second_m_type == 0x20:
            bruteforce_accept_request(second, first, dont_generate_keys)
        else:
            error_message(packet_order='second')
    elif first_m_type == 0x20:
        if second_m_type == 0x00:
            bruteforce_accept_request(first, second, dont_generate_keys)
        elif second_m_type == 0x20:
            bruteforce_two_join_accepts(first, second, dont_generate_keys)
        else:
            error_message(packet_order='second')
    else:
        error_message(packet_order='first')


def error_message(packet_order):
    print( "\nMake sure the {0} packet provided is a valid JoinRequest or JoinAccept \n".format(packet_order))


if __name__ == '__main__':

    try:
        print ("\n*****************************************************")
        print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
        print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
        print ("*****************************************************\n")

        parser = argparse.ArgumentParser(description='This script receives 2 JoinAccepts, 2 JoinRequests or a pair or JoinRequest/JoinAccept in Base64 and tries to decrypt its AppKey with a set of possible keys which can be provided in a file or can be generated on the fly.')
        requiredGroup = parser.add_argument_group('Required arguments')
        requiredGroup.add_argument("-f", "--first",
                                    help= "Packet in Base64 format (JoinRequest/JoinAccept) to be bruteforced. eg. -f IHvAP4MXo5Qo6tdV+Yfk08o=",
                                    required = True)
        requiredGroup.add_argument("-s", "-second", "--second",
                                    help= "Packet in Base64 format (JoinRequest/JoinAccept) to be bruteforced. eg. -s AMQAAAAAhQAAAgAAAAAAAADcYldcgbc=",
                                    required = True)
        parser.add_argument("-k", "--keys",
                            help = "File containing a list of keys, separated by \\n. Will use /auditing/analyzers/bruteForcer/keys.txt by default",
                            default = "../../auditing/analyzers/bruteforcer/keys.txt")           
        parser.add_argument("--dont-generate",
                            action= "store_true",
                            help = "Select this options if you don't want to generate keys on the fly with the following combinations:\n 1- Combine the first byte and the last fifteeen bytes. eg. AABBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n 2- Combine even and odd bytes position equally. eg. AABBAABBAABBAABBAABBAABBAABBAABB\n 3- The first 14 bytes in 00 and combine the last 2. eg. 0000000000000000000000000000BA01",
                            default = False)

        options = parser.parse_args()

        validateKeys(options.first, options.second, options.keys, options.dont_generate)
    
    except KeyboardInterrupt:
        exit(0)

