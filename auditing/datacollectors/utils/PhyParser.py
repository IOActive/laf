import sys, os, json, logging
import lorawanwrapper.LorawanWrapper as LorawanWrapper

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

# This function is meant to be reused by every collector
def setPHYPayload(data):
    packet = {}
    stringPHY = LorawanWrapper.printPHYPayload(data)

    # If the PHYPayload couldn't be parsed, just put the error and return
    if "Error" in stringPHY:
        packet['error'] = stringPHY
        return packet

    try:
        jsonPHY = json.loads(stringPHY)
    except Exception as e:
        logging.error('Error parsing PHYPayload: {0}'.format(e))
        packet['error'] = stringPHY
        return packet

    # The following fields are shared by every packet
    packet['m_type'] = jsonPHY['mhdr']['mType']
    packet['major'] = jsonPHY['mhdr']['major']
    packet['mic'] = jsonPHY['mic']

    if packet['m_type'] == "JoinRequest":
        # It's a JoinRequest
        packet['join_eui'] = jsonPHY['macPayload']['joinEUI']
        packet['dev_eui'] = jsonPHY['macPayload']['devEUI']
        packet['dev_nonce'] = jsonPHY['macPayload']['devNonce']
        return packet
    elif packet['m_type'] == "JoinAccept":
        # It's a JoinAccept Nothing to see  
        return packet
    elif packet['m_type'] == "UnconfirmedDataDown" or packet['m_type'] == "ConfirmedDataDown" :        
        # These are fCtrl fields for downlink packets 
        packet['adr'] = jsonPHY['macPayload']['fhdr']['fCtrl']['adr']
        packet['class_b'] = jsonPHY['macPayload']['fhdr']['fCtrl']['classB']
        packet['adr_ack_req'] = jsonPHY['macPayload']['fhdr']['fCtrl']['adrAckReq']
        packet['ack'] = jsonPHY['macPayload']['fhdr']['fCtrl']['ack']
        # These fields are common for every data packet
        packet['dev_addr'] = jsonPHY['macPayload']['fhdr']['devAddr']
        packet['f_count'] = jsonPHY['macPayload']['fhdr']['fCnt']

        if 'fOpts' in jsonPHY['macPayload']['fhdr'] and jsonPHY['macPayload']['fhdr']['fOpts'] is not None:
            if isinstance(jsonPHY['macPayload']['fhdr']['fOpts'],dict):
                packet['f_opts'] = json.dumps(jsonPHY['macPayload']['fhdr']['fOpts'])
            elif isinstance(jsonPHY['macPayload']['fhdr']['fOpts'],list):
                packet['f_opts'] = json.dumps(jsonPHY['macPayload']['fhdr']['fOpts'])
            else:
                packet['f_opts'] = str(jsonPHY['macPayload']['fhdr']['fOpts'])
            
        if 'f_port' in jsonPHY['macPayload']['fhdr'] and jsonPHY['macPayload']['fhdr']['fPort'] is not None:
            packet['f_port'] = jsonPHY['macPayload']['fhdr']['fPort']

        return packet
    elif packet['m_type'] == "UnconfirmedDataUp" or packet['m_type'] == "ConfirmedDataUp":
        # These are fCtrl fields for uplink packets 
        packet['adr'] = jsonPHY['macPayload']['fhdr']['fCtrl']['adr']
        packet['f_pending'] = jsonPHY['macPayload']['fhdr']['fCtrl']['fPending']
        packet['ack'] = jsonPHY['macPayload']['fhdr']['fCtrl']['ack']
        # These fields are common for every data packet
        packet['dev_addr'] = jsonPHY['macPayload']['fhdr']['devAddr']
        packet['f_count'] = jsonPHY['macPayload']['fhdr']['fCnt']
        
        if 'fOpts' in jsonPHY['macPayload']['fhdr'] and jsonPHY['macPayload']['fhdr']['fOpts'] is not None:
            if isinstance(jsonPHY['macPayload']['fhdr']['fOpts'],dict):
                packet['f_opts'] = json.dumps(jsonPHY['macPayload']['fhdr']['fOpts'])
            elif isinstance(jsonPHY['macPayload']['fhdr']['fOpts'],list):
                packet['f_opts'] = json.dumps(jsonPHY['macPayload']['fhdr']['fOpts'])
            else:
                packet['f_opts'] = str(jsonPHY['macPayload']['fhdr']['fOpts'])

        if 'f_port' in jsonPHY['macPayload']['fhdr'] and jsonPHY['macPayload']['fhdr']['fPort'] is not None:
            packet['f_port'] = jsonPHY['macPayload']['fhdr']['fPort']
        return packet

    return packet