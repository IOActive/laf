# LoRaWAN Security Framework - BruteForcer.py
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import argparse, base64,sys
import lorawanwrapper.LorawanWrapper as LorawanWrapper

def validateKeys(jr, ja, keysPath, dont_generate_keys):
    keys = list()
    with open(keysPath) as f:
        for k in f:
            # Fetch keys in byte format. Needed by ctypes
            keys.append(bytes(k.rstrip().upper(), encoding='utf-8'))  
    
    jr_decoded=base64.b64decode(jr)
    jr_m_type= jr_decoded[0] & 0xE0

    ja_decoded=base64.b64decode(ja)
    ja_m_type= ja_decoded[0] & 0xE0

    if jr_m_type != 0x00 or ja_m_type != 0x20:
        print( "\nMake sure you provided a valid JoinRequest and JoinAccept \n")
        return
   
    jr_result = LorawanWrapper.testAppKeysWithJoinRequest(keys, jr, dont_generate_keys)  

    if len(jr_result) > 0:
        
        # Convert valid keys into bytes
        valid_keys= list()
        for valid_key in jr_result.split():
            valid_keys.append(bytes(valid_key.upper(), encoding='utf-8'))

        ja_result = LorawanWrapper.testAppKeysWithJoinAccept(valid_keys, ja, dontGenerateKeys= True)

        if len(ja_result) > 0:
            print ("\n**** Key found: %s **** \n"%(ja_result.split()[0]))


if __name__ == '__main__':

    try:
        print ("\n*****************************************************")
        print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
        print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
        print ("*****************************************************\n")

        parser = argparse.ArgumentParser(description='This script receives a JoinAccept or JoinRequest in Base64 and tries to decrypt its AppKey with a set of possible keys which can be provided in a file or can be generated on the fly.')
        requiredGroup = parser.add_argument_group('Required arguments')
        requiredGroup.add_argument("-a", "--accept",
                                    help= "Join Accept in Base64 format to be bruteforced. eg. -a IHvAP4MXo5Qo6tdV+Yfk08o=",
                                    required = True)
        requiredGroup.add_argument("-r", "--request",
                                    help= "Join Request in Base64 format to be bruteforced. eg. -r AMQAAAAAhQAAAgAAAAAAAADcYldcgbc=",
                                    required = True)
        parser.add_argument("-k", "--keys",
                            help = "File containing a list of keys, separated by \\n. Will use /auditing/analyzers/bruteForcer/keys.txt by default",
                            default = "../../auditing/analyzers/bruteforcer/keys.txt")           
        parser.add_argument("--dont-generate",
                            action= "store_true",
                            help = "Select this options if you don't want to generate keys on the fly with the following combinations:\n 1- Combine the first byte and the last fifteeen bytes. eg. AABBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n 2- Combine even and odd bytes position equally. eg. AABBAABBAABBAABBAABBAABBAABBAABB\n 3- The first 14 bytes in 00 and combine the last 2. eg. 0000000000000000000000000000BA01",
                            default = False)

        options = parser.parse_args()

        validateKeys(options.request, options.accept, options.keys, options.dont_generate)
    
    except KeyboardInterrupt:
        exit(0)

