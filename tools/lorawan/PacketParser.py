# LoRaWAN Security Framework - PacketParser
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import sys, argparse, os
import lorawanwrapper.LorawanWrapper as LorawanWrapper


if __name__ == '__main__':

    # TEST PHYPAYLOADS

    # A JoinRequest: AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=
    # A JoinAccept: IB1scNmwJRA32RfMbvwe3oI=
    # An UnconfirmedDataUp: QMTBfwGCEQADBV3/YTIQt7ibgXm3ExKn3caL453u5PTAj/EUU+UoeTTVUg==
    # An UnconfirmedDataDown: YMTBfwGFNwADJP//Ab5NjL8=

    try:
        print ("\n*****************************************************")
        print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
        print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
        print ("*****************************************************\n")

        parser = argparse.ArgumentParser(description='This script parses and prints a single LoRaWAN PHYPayload data in Base64. It does the inverse as packetCrafter.py, so the output of that script can be used here and vice-versa.')

        requiredGroup = parser.add_argument_group('Required arguments')
        requiredGroup.add_argument("-d", "--data",
                            help= 'Base64 data to be parsed. eg. -d AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=',
                            default=None,
                            required = True
                            )
        parser.add_argument("-k", "--key",
                        help= 'Enter a device AppKey or AppSKey depending on the packet to be decrypted (join accept or data packet). Must be in hex format, a total of 32 characters / 16 bytes. eg. 00112233445566778899AABBCCDDEEFF',
                        default=None)

        options= parser.parse_args()  
        print ("Parsed data: %s \n"%(LorawanWrapper.printPHYPayload(options.data,options.key)))

    except KeyboardInterrupt:
        exit(0)
