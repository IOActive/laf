# LoRaWAN Security Framework - SessionKeysGenerator
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import os, sys, argparse, json
import lorawanwrapper.LorawanWrapper as LorawanWrapper

if __name__ == '__main__':
    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This script receives a JoinAccept and a JoinRequest in Base64, and an AppKey to generate the session keys. An example of the usage: \npython sessionKeysGenerator.py -a IB1scNmwJRA32RfMbvwe3oI= -r AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU= -k f5a3b185dfe452c8edca3499abcd0341')
    requiredGroup = parser.add_argument_group('Required arguments')

    requiredGroup.add_argument("-a", "--jaccept",
                        help= 'JoinAccept payload in base64',
                        required = True
                        )
    requiredGroup.add_argument("-r", "--jrequest",
                        help= 'JoinRequest payload in base64',
                        required = True
                        )
    requiredGroup.add_argument("-k", "--key",
                        help= 'Enter a device AppKey (in hex format, a total of 32 characters / 16 bytes). eg. 00112233445566778899AABBCCDDEEFF',
                        required = True
                        )                                                          

    options = parser.parse_args()

    json_result = LorawanWrapper.generateSessionKeysFromJoins(options.jrequest, options.jaccept, options.key)
    keys= json.loads(json_result)  
    print ("NwkSKey: %s\nAppSKey: %s"%(keys["nwkSKey"], keys["appSKey"]))