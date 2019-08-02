# LoRaWAN Security Framework - MicGenerator
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import argparse, sys
import lorawanwrapper.LorawanWrapper as LorawanWrapper

if __name__ == '__main__':
    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This scripts receives a PHYPayload packet in Base64 and a key which can be the NwkSKey of the AppKey depending on the packet type and generates the new MIC.')
    requiredGroup = parser.add_argument_group('Required arguments')

    requiredGroup.add_argument("-d", "--data",
                            help= 'Base64 data to be signed. eg. -d AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=',
                            default=None,
                            required = True)
    requiredGroup.add_argument("-k","--key",
                            help= 'Enter the new key (in hex format, a total of 32 characters / 16 bytes) to sign packets (calculate and add a new MIC). Note that for JoinRequest/JoinAccept it must be the AppKey, and the NwkSKey for Data packets. This cannot be validated beforehand by this program. eg. 00112233445566778899AABBCCDDEEFF',
                            required = True,
                            default=None)          
    parser.add_argument("--jakey",
                            help= '[JoinAccept ONLY]. Enter the key used to encrypt the JoinAccept previously (in hex format, a total of 32 characters / 16 bytes). This cannot be validated beforehand by this program. eg. 00112233445566778899AABBCCDDEEFF. A valid key sample for the JoinAccept "IB1scNmwJRA32RfMbvwe3oI=" is "f5a3b185dfe452c8edca3499abcd0341"',
                            default=None)                                                                        
    options = parser.parse_args()

    print ("\nYour PHYPayload with the new MIC is %s\n"%(LorawanWrapper.generateValidMIC(options.data, options.key, options.jakey)))