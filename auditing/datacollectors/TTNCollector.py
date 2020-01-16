import argparse
import sys
import time
import logging
import os
import websocket
import threading
import json
import requests
from datetime import datetime
import dateutil.parser
from time import sleep
import auditing.datacollectors.utils.PhyParser as phy_parser
from auditing.datacollectors.utils.PacketPersistence import save

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

account_login_url = os.environ['ACCOUNT_LOGIN_URL'] if 'ACCOUNT_LOGIN_URL' in os.environ else 'https://account.thethingsnetwork.org/api/v2/users/login' # 'https://account.thethingsnetwork.org/api/v2/users/login'
login_url = os.environ['LOGIN_URL'] if 'LOGIN_URL' in os.environ else 'https://console.thethingsnetwork.org/login'
access_token_url = os.environ['ACCESS_TOKEN_URL'] if 'ACCESS_TOKEN_URL' in os.environ else 'https://console.thethingsnetwork.org/refresh'
ws_url = os.environ['WS_URL'] if 'WS_URL' in os.environ else 'wss://console.thethingsnetwork.org/api/events/644/lta0xryg/websocket?version=v2.6.11'

def init_packet_writter_message():
    packet_writter_message = dict()
    packet_writter_message['packet'] = None
    packet_writter_message['messages'] = list()
    return packet_writter_message

class TTNCollector:
    def __init__(self, data_collector_id, organization_id, user, password, gateway_id):
        self.data_collector_id = data_collector_id
        self.organization_id = organization_id
        self.user = user
        self.password = password
        self.gateway_id = gateway_id
        self.ws = None
        self.session = None
        self.last_seen = None
        self.connected = "DISCONNECTED"
        self.disabled = False
        self.manually_disconnected = None
        # The data sent to the MQTT queue, to be written by the packet writer. It must have at least one MQ message
        self.packet_writter_message = init_packet_writter_message()
        # Dict containing location 
        self.location = dict()
    
    def connect(self):
        self.session = login(self.user, self.password)
        if self.session:
            self.connected = "DISCONNECTED"
            self.manually_disconnected = None
            data_access = fetch_access_token(self.session)
            access_token = data_access.get('access_token')
            expires = data_access.get('expires')

            self.ws = websocket.WebSocketApp(ws_url, on_message = on_message, on_error = on_error, on_close = on_close)
            self.ws.access_token = access_token
            self.ws.gateway = self.gateway_id
            self.ws.organization_id = self.organization_id
            self.ws.data_collector_id = self.data_collector_id
            self.ws.on_open = on_open
            self.ws.user_data = self
            self.ws.is_closed = False

            self.ws.packet_writter_message = self.packet_writter_message
            self.ws.location = self.location

            thread = threading.Thread(target=self.ws.run_forever)
            thread.daemon = True
            thread.start()

            thread = threading.Thread(target=schedule_refresh_token, args=(self.ws, self.session, expires))
            thread.daemon = True
            thread.start()
        else:
            logging.error("Couldn't get session in TTN")  

    
    def disconnect(self):
        self.manually_disconnected = True
        logging.info("Manually disconnected to gw: {}".format(self.gateway_id))
        try:
            self.ws.close()
        except Exception as exc:
            logging.error("Error closing socket: " + str(exc))

def on_message(ws, raw_message):

    # The contents of many messages is an 'h'. We don't want to print that.
    if len(raw_message)>1:
        logging.info("Message: {}".format(raw_message))

    # Remove data format stuff
    raw_message = raw_message.replace('\\"', '"')

    # Save the message that originates the packet
    ws.packet_writter_message['messages'].append(
        {
            'topic': None,
            'message': raw_message[0:4096],
            'data_collector_id': ws.data_collector_id
        }
    )

    ws.user_data.last_seen = datetime.now()
    
    has_to_parse = False
    if 'gateway downlink' in raw_message:
        has_to_parse = True
        message = raw_message[20:-2]
    elif 'gateway uplink' in raw_message:
        has_to_parse = True
        message = raw_message[18:-2]
    elif 'gateway join request' in raw_message:
        has_to_parse = True
        message = raw_message[24:-2]
    elif 'gateway join accept' in raw_message:
        has_to_parse = True
        message = raw_message[23:-2]
    elif 'gateway status' in raw_message and 'location' in raw_message:
        # Check if the location is given in this message. If so, save it and add it in subsequent messages

        try:
            message = raw_message[18:-2].replace('\\"', '"')
            status_message = json.loads(message)

            ws.location['longitude']= status_message.get('status').get('location').get('longitude')
            ws.location['latitude']= status_message.get('status').get('location').get('latitude')
            ws.location['altitude']= status_message.get('status').get('location').get('altitude')
        
        except Exception as e:
            logging.error("Error when fetching location in TTNCollector:" + str(e) + " Message: " + raw_message)
    elif len(raw_message)>1:
        message = raw_message.replace('\\"', '"')
    else:
        return

    try:
        if has_to_parse:
            message = json.loads(message)
            packet  = phy_parser.setPHYPayload(message.get('payload'))
            packet['chan'] = None
            packet['stat'] = None
            packet['lsnr'] = message.get('snr', None)
            packet['rssi'] = message.get('rssi', None)
            packet['tmst'] = datetime.timestamp(dateutil.parser.parse(message.get('timestamp', None))) * 1000
            packet['rfch'] = message.get('rfch', None)
            packet['freq'] = message.get('frequency', None)
            packet['modu'] = None
            packet['datr'] = None
            packet['codr'] = message.get('coding_rate', None)
            packet['size'] = None
            packet['data'] = message.get('payload')

            if len(ws.location)>0:
                packet['latitude'] = ws.location['latitude']
                packet['longitude'] = ws.location['longitude']
                packet['altitude'] = ws.location['altitude']
                
                # Reset location
                ws.location={}

            packet['app_name'] = None
            packet['dev_name'] = None

            gw = ws.gateway
            packet['gateway'] = gw.replace('eui-', '') if gw else None

            packet['seqn'] = None
            packet['opts'] = None
            packet['port'] = None

            packet['date'] = datetime.now().__str__() 
            packet['dev_eui'] = message.get('dev_eui')
            packet['data_collector_id'] = ws.data_collector_id
            packet['organization_id'] = ws.organization_id
                
            ws.packet_writter_message['packet']= packet

        # Save the packet
        save(ws.packet_writter_message, ws.data_collector_id)

        logging.debug('Message received from TTN saved in DB: {0}.'.format(ws.packet_writter_message))

        # Reset this variable
        ws.packet_writter_message = init_packet_writter_message()

    except Exception as e:
        logging.error("Error creating Packet in TTNCollector:" + str(e) + " Message: " + raw_message)




def on_error(ws, error):
    logging.error("Error ws: {}".format(str(error)))

def on_close(ws): # similar to on_disconnect
    ws.close()
    ws.is_closed = True
    logging.info("Disconnected to gw: {}".format(ws.gateway_id))

def on_open(ws): # similar to on_connect
    ws.send('["gateway:'+ws.gateway+'"]')
    ws.send('["token:'+ws.access_token+'"]')
    ws.user_data.connected = "CONNECTED"
    ws.is_closed = False
    logging.info("Connected to GW:" + ws.gateway)

def login(user, password):
	ses = requests.Session()
	ses.headers['Content-type'] = 'application/json'
	res = ses.post(account_login_url, data=json.dumps({"username": user, "password": password}))	
	ses.get(login_url)

	return ses if res.status_code == 200 else None

def fetch_access_token(ses):
    logging.info('ses' + str(ses.cookies))
    res = ses.get(access_token_url, timeout = 30)
    logging.info('res' + str(res))
    return res.json()

def schedule_refresh_token(ws, session, first_expires):
    expires = first_expires
    while(not ws.is_closed):
        logging.info("expires: " + str(expires))
        if expires:
            dt = datetime.fromtimestamp(expires/1000)
            logging.info("sleep: " + str((dt-datetime.now()).seconds-60))
            sleep((dt-datetime.now()).seconds-900) # -15 min
            logging.info("is closed: " + str(ws.is_closed))
        try:            
            data_access = fetch_access_token(session)
            access_token = data_access.get('access_token')
            expires = data_access.get('expires')
            ws.access_token = access_token
            logging.info("access token: " + access_token)
            ws.send('["token:'+access_token+'"]')
        except Exception as exc:
            logging.error('error fetching access token: ' + str(exc))
            expires = None

if __name__ == '__main__':
    from auditing.db.Models import DataCollector, DataCollectorType, Organization, commit, rollback

    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This script connects to TTN with a TTN account and saves messages into the DB.')

    requiredGroup = parser.add_argument_group('Required arguments')
    
    requiredGroup.add_argument('--user',
                        help='TTN username')
    requiredGroup.add_argument('--pwd',
                        help='TTN password')
    requiredGroup.add_argument('--gw-id',
                        help='The id of the gateway you want to connect. This id has the format eui-0011AABBCCDDEEFF. Make sure to provide this id using the whole string.')
    parser.add_argument('--collector-id',
                                help = 'The ID of the dataCollector. This ID will be associated to the packets saved into DB. eg. --id 1')
    parser.add_argument('--organization-id',
                            help = 'The ID of the dataCollector. This ID will be associated to the packets saved into DB. eg. --id 1',
                            default= None)

    options = parser.parse_args()

    # Get the organization
    if options.organization_id:
        organization_obj = Organization.find_one(options.organization_id)

        if organization_obj is None:
            print("Organization doesn't exist. Please provide a valid ID")
            exit(0)

    else:
        organization_quant = Organization.count()

        if organization_quant > 1:
            print("There are more than one organizations in the DB. Provide the Organization DB explicitly.")

        elif organization_quant == 1:
            organization_obj = Organization.find_one()

        else:
            organization_obj = Organization(name = "Auto-generated Organization")
            organization_obj.save()

    # Get the data collector
    collector_obj = None
    if options.collector_id:
        collector_obj = DataCollector.find_one(options.collector_id)

        if collector_obj is None:
            print("DataCollector doesn't exist. Please provide a valid ID")
            exit(0)
        
    else:

        if options.user and options.pwd and options.gw_id:
            collector_type_obj = DataCollectorType.find_one_by_type("ttn_collector")

            if collector_type_obj is None:
                collector_type_obj= DataCollectorType(
                    type = "ttn_collector",
                    name= "ttn_collector")
                collector_type_obj.save()

            collector_obj= DataCollector.find_one_by_type_and_user_and_password_and_gateway_id(collector_type_obj.id, options.user, str.encode(options.pwd), options.gw_id)

            if collector_obj is None:
                collector_obj= DataCollector(
                    data_collector_type_id= collector_type_obj.id,
                    name=options.gw_id,
                    organization_id = organization_obj.id,
                    user=options.user,
                    password=str.encode(options.pwd)
                )
                collector_obj.save()
        
        else:
            print('TTN user and password must be provided if not provided a collector ID.')
            exit(0)

    connector = TTNCollector(
                data_collector_id = collector_obj.id,
                organization_id = collector_obj.organization_id,
                user = collector_obj.user,
                password = collector_obj.password.decode(),
                gateway_id = collector_obj.name
            )

    connector.connect()

    while(True):
        time.sleep(5)
        try:
            commit()
            logging.debug('Commit done!')
        except Exception as exc:
            logging.error('Error at commit:', exc)
            logging.info('Rolling back the session')
            rollback()