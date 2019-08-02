# LoRaWAN Security Framework - PacketCrafter
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import sys, argparse, os
import lorawanwrapper.LorawanWrapper as LorawanWrapper


def parseJSONtoPHY(json, key, nwkskey):
    if json is None:
        print ("JSON not specified. Exiting.")
        return
    
    b64 = LorawanWrapper.marshalJsonToPHYPayload(json, key, nwkskey)

    print ("PHYPayload is %s \n"%(b64))

if __name__ == '__main__':

# TEST JSONs 

# {"mhdr":{"mType":"JoinRequest","major":"LoRaWANR1"},"macPayload":{"joinEUI":"55d239ac716f234d","devEUI":"b827eb891cf50003","devNonce":51639},"mic":"7005c4a5"}
# {"mhdr":{"mType":"JoinAccept","major":"LoRaWANR1"},"macPayload":{"bytes":"HWxw2bAlEDfZF8xu"},"mic":"fc1ede82"}
# {"mhdr":{"mType":"UnconfirmedDataUp","major":"LoRaWANR1"},"macPayload":{"fhdr":{"devAddr":"017fc1c4","fCtrl":{"adr":true,"adrAckReq":false,"ack":false,"fPending":false,"classB":false},"fCnt":17,"fOpts":[{"cid":"LinkADRReq","payload":{"channelMaskAck":true,"dataRateAck":false,"powerAck":true}}]},"fPort":93,"frmPayload":[{"bytes":"/2EyELe4m4F5txMSp93Gi+Od7uT0wI/xFFPlKA=="}]},"mic":"7934d552"}
# {"mhdr":{"mType":"UnconfirmedDataDown","major":"LoRaWANR1"},"macPayload":{"fhdr":{"devAddr":"017fc1c4","fCtrl":{"adr":true,"adrAckReq":false,"ack":false,"fPending":false,"classB":false},"fCnt":55,"fOpts":[{"cid":"LinkADRReq","payload":{"dataRate":2,"txPower":4,"chMask":[true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true],"redundancy":{"chMaskCntl":0,"nbRep":1}}}]},"fPort":null,"frmPayload":null},"mic":"be4d8cbf"}

# The AppKey for these joins: F5A3B185DFE452C8EDCA3499ABCD0341

    try:
        print ("\n*****************************************************")
        print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
        print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
        print ("*****************************************************\n")

        parser = argparse.ArgumentParser(description='This script receives a lorawan JSON packet and tranforms it to Base64. It does the inverse as packetParser.py, so the output of that script can be used here and vice-versa.')
        requiredGroup = parser.add_argument_group('Required arguments')
        requiredGroup.add_argument("-j", "--json",
                                    help= """JSON object to parse, between quotes. eg. -j '{"mhdr":{"mType":"JoinRequest","major":"LoRaWANR1"},"macPayload":{"joinEUI":"55d239ac716f234d","devEUI":"b827eb891cf50003","devNonce":51639},"mic":"7005c4a5"}' """,
                                    required = True)
        parser.add_argument("-k", "--key",
                        help= 'Enter a device AppSKey or AppKey (in hex format, a total of 32 characters / 16 bytes) to encrypt the FRMPayload or a Join Accept. eg. F5A3B185DFE452C8EDCA3499ABCD0341',
                        default=None)
        parser.add_argument("--nwkskey",
                            help= "Enter the network session key if you'd like to generate a data packet with a valid MIC."
                    )


        options = parser.parse_args()

        parseJSONtoPHY(options.json, options.key, options.nwkskey)
    
    except KeyboardInterrupt:
        exit(0)