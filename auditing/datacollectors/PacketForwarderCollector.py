# LoRaWAN Security Framework - GenericMqttCollector
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import sys,argparse, datetime, json, os, re, time,logging, threading, socket, traceback

import auditing.datacollectors.utils.PhyParser as phy_parser
from auditing.datacollectors.utils.PacketPersistence import save

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

# This dict keeps track of the 
gateways_location={}

def init_packet_writter_message():
    packet_writter_message = dict()
    packet_writter_message['packet'] = None
    packet_writter_message['messages'] = list()
    return packet_writter_message

class PacketForwarderCollector:

    def __init__(self, data_collector_id, organization_id, port):
        self.data_collector_id = data_collector_id
        self.organization_id = organization_id
        self.port = port
        self.stop_thread=True
        # The data sent to the MQTT queue, to be written by the packet writer. It must have at least one MQ message
        self.packet_writter_message = init_packet_writter_message()

    def connect(self):
        self.stop_thread=False
        # Launch listener() in a thread       
        self.listener=threading.Thread(target=listener,args = (self,))
        self.listener.daemon = True
        self.listener.start()

    def disconnect(self):
        self.stop_thread= True
        self.listener.join()

def listener(client):

    udp_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_listener.bind(('', client.port))
    
    while True:

        if client.stop_thread:
            break

        payload, source_address = udp_listener.recvfrom(65565)

        
        if len(payload)>4:
            try:
                if chr(payload[4]) == '{':
                    udp_message= json.loads(payload[4:].decode("utf-8") )
                    header= payload[0:4]
                else:
                    udp_message= json.loads(payload[12:].decode("utf-8") )
                    header= payload[0:12]
            except Exception as e:
                logging.debug('Skipping packet: {0}'.format(payload))
                skip_packet= True
        else:
            logging.debug('Skipping packet: {0}'.format(payload))
            skip_packet= True
        
        
        try:
            if not skip_packet:

                standardPacket={}

                if "stat" in udp_message:
                    
                    pkt = udp_message.get("stat")

                    location = {}
                    if 'lati' in pkt:
                        location['latitude'] = pkt.get('lati')
                    if 'long' in pkt:
                        location['longitude'] = pkt.get('long') 
                    if 'alti' in pkt:
                        location['altitude'] = pkt.get('alti')

                    if len(location) > 0:
                        gateway= get_gateway_id(header)
                        gateways_location[gateway]=location

                if "rxpk" in udp_message or "txpk" in udp_message:
                    
                    pkt = udp_message.get("rxpk")[0] if "rxpk" in udp_message else udp_message.get("txpk")

                    standardPacket = phy_parser.setPHYPayload(pkt.get('data'))
                    standardPacket['chan'] = pkt.get('chan', None)
                    standardPacket['stat'] = pkt.get('stat', None)
                    standardPacket['lsnr'] = pkt.get('lsnr', None)
                    standardPacket['rssi'] = pkt.get('rssi', None)
                    standardPacket['tmst'] = pkt.get('tmst', None)
                    standardPacket['rfch'] = pkt.get('rfch', None)
                    standardPacket['freq'] = pkt.get('freq', None)
                    standardPacket['modu'] = pkt.get('modu', None)
                    standardPacket['datr'] = json.dumps(parse_datr(pkt.get('datr', None)))
                    standardPacket['codr'] = pkt.get('codr', None)
                    standardPacket['size'] = pkt.get('size', None)
                    standardPacket['data'] = pkt.get('data', None)
                
                    gateway= get_gateway_id(header)
                    if gateway:

                        standardPacket['gateway'] = gateway

                        if gateway in gateways_location:
                            standardPacket['latitude']= gateways_location[gateway]['latitude']
                            standardPacket['longitude']= gateways_location[gateway]['longitude']
                            standardPacket['altitude']= gateways_location[gateway]['altitude']
                    
                    standardPacket['date'] = datetime.datetime.now().__str__() 
                    standardPacket['data_collector_id'] = client.data_collector_id
                    standardPacket['organization_id'] = client.organization_id

                    client.packet_writter_message['packet']= standardPacket
                    
                    logging.debug('Message received: {0} \n{1}'.format(payload, json.dumps(standardPacket)))

            # Save this message an topic into MQ
            client.packet_writter_message['messages'].append(
                {
                    'topic':None,
                    'message':payload.decode("utf-8"),
                    'data_collector_id': client.data_collector_id
                }
            )

            # Save the packet
            save(client.packet_writter_message, client.data_collector_id)     

            # Reset packet_writter_message
            client.packet_writter_message = init_packet_writter_message()

        except Exception as e:
            logging.error("Error creating Packet in PacketForwarderCollector: {0}. Message: {1}".format(e,payload))  
            traceback.print_exc(file=sys.stdout)

def get_gateway_id(header):   
    gw = None  
    
    if len(header) > 4:
        gw = ""
        for pos in range(4,12):
            gw+= "{:02x}".format(header[pos])

    return gw

def parse_datr(encoded_datr):
    datr = {}
    search = re.search('SF(.*)BW(.*)', encoded_datr)
    if search:
        datr["spread_factor"] = search.group(1)
        datr["bandwidth"] = search.group(2)
    return datr


if __name__ == '__main__':

    from auditing.db.Models import DataCollector, DataCollectorType, Organization, commit, rollback

    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This script receives UDP packets from the UDP proxy in the gateway packet_forwarder format and persists them.')

    requiredGroup = parser.add_argument_group('Required arguments')
    requiredGroup.add_argument("-n", "--name",
                                help= "Unique string identifier of the Data Collector. eg. --name semtech_collector",
                                required = True)
    requiredGroup.add_argument('-p','--port',
                        help='Port where to listen for UDP packets. --port 1702.',
                        type=int) 
    parser.add_argument('--collector-id',
                        type=int,
                        help = 'The ID of the dataCollector. This ID will be associated to the packets saved into DB. eg. --id 1')
    parser.add_argument('--organization-id',
                        help = 'The ID of the dataCollector. This ID will be associated to the packets saved into DB. eg. --id 1',
                        type=int,
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

        if options.port:
            collector_type_obj = DataCollectorType.find_one_by_type("forwarder_collector")

            if collector_type_obj is None:
                collector_type_obj= DataCollectorType(
                    type = "forwarder_collector",
                    name= "forwarder_collector")
                collector_type_obj.save()

            collector_obj= DataCollector.find_one_by_name_and_dctype_id(collector_type_obj.id, options.name)

            if collector_obj is None:
                collector_obj= DataCollector(
                    data_collector_type_id= collector_type_obj.id,
                    name= options.name,
                    organization_id = organization_obj.id,
                    ip='N/A',
                    port= str(options.port))
                collector_obj.save()
        
        else:
            print('Datacollector IP and port must be provided if not provided a collector ID.')
            exit(0)

    connector = PacketForwarderCollector(
        data_collector_id = collector_obj.id,
        organization_id = collector_obj.organization_id,
        port = int(collector_obj.port))

    connector.connect()

    while(True):
        time.sleep(5)
        try:
            commit()
            logging.debug('Commit done!')
        except KeyboardInterrupt as ki:
            connector.disconnect()
            commit()
            exit(0)
        except Exception as exc:
            logging.error('Error at commit:', exc)
            logging.info('Rolling back the session')
            rollback()