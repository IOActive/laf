# LoRaWAN Security Framework - DataPacketsBurteforcer.py
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import argparse, base64,sys
import lorawanwrapper.LorawanWrapper as LorawanWrapper

def bruteForceDataPacket(data, keys_path, net_ids_path):
    keys = list()
    with open(keys_path) as f:
        for k in f:
            # Fetch keys in byte format. Needed by ctypes
            keys.append(bytes(k.rstrip().upper(), encoding='utf-8'))  
    
    net_ids = list()
    with open(net_ids_path) as f:
        for n in f:
            # Fetch net_ids in byte format. Needed by ctypes
            net_ids.append(bytes(n.rstrip().upper(), encoding='utf-8'))
    
    data_decoded=base64.b64decode(data)
    data_type= data_decoded[0] & 0xE0

    if data_type == 0x20 or data_type == 0x40 or data_type == 0x80 or data_type == 0xA0:
        bruteforce_result = LorawanWrapper.test_app_keys_and_net_ids_with_data_packet(keys, data, net_ids) 
    else:
        print( "\nMake sure you provided a valid data packet \n")
        return    

    if len(bruteforce_result) > 0:

        print ("\n**** Key found: {0} **** \n".format(bruteforce_result))
        print(bruteforce_result)
        
        # # Convert valid keys into bytes and print them
        # for valid_key in bruteforce_result.split():
        #    print(bytes(valid_key.upper(), encoding='utf-8'))

    else:
        print("\n**** No Keys found **** \n")

if __name__ == '__main__':

    try:
        print ("\n*****************************************************")
        print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
        print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
        print ("*****************************************************\n")

        parser = argparse.ArgumentParser(description='This script receives a JoinAccept or JoinRequest in Base64 and tries to decrypt its AppKey with a set of possible keys which can be provided in a file or can be generated on the fly.')
        requiredGroup = parser.add_argument_group('Required arguments')
        requiredGroup.add_argument("-d", "--data",
                                    help= "Data packet to bruteforce",
                                    required = True)
        parser.add_argument("-k", "--keys",
                            help = "File containing a list of keys, separated by \\n. Will use /auditing/analyzers/bruteForcer/keys.txt by default",
                            default = "../../auditing/analyzers/bruteforcer/keys.txt")           
        parser.add_argument("-n", "--net-ids",
                            help = "File containing a list of NetIDs, separated by \\n. Will use /auditing/analyzers/bruteForcer/net_ids.txt by default",
                            default = "../../auditing/analyzers/bruteforcer/net_ids.txt")           

        options = parser.parse_args()

        bruteForceDataPacket(options.data, options.keys, options.net_ids)
    
    except KeyboardInterrupt:
        exit(0)

