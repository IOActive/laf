# LoRaWAN Security Framework - LoraServerIOCollector
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import sys,argparse, datetime, json, base64, os, traceback, json, re, time,logging
# The MQTT client used and its documentation can be found in https://github.com/eclipse/paho.mqtt.python
import paho.mqtt.client as mqtt
import auditing.datacollectors.utils.PhyParser as phy_parser
from auditing.datacollectors.utils.PacketPersistence import save

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

def init_packet_writter_message():
    packet_writter_message = dict()
    packet_writter_message['packet'] = None
    packet_writter_message['messages'] = list()
    return packet_writter_message

class LoraServerIOCollector:
    
    TIMEOUT = 60

    def __init__(self, data_collector_id, organization_id, host, port, ssl, user, password, topics):
        self.data_collector_id = data_collector_id
        self.organization_id = organization_id
        self.host = host
        self.port = port
        self.ssl = ssl
        self.user = user
        self.password = password
        self.topics = topics
        self.mqtt_client = None
        # This var saves half of the information (from the topic gateway/gw_id/rx) to be persisted
        self.prev_packet = None
        # The data sent to the MQTT queue, to be written by the packet writer. It must have at least one MQ message
        self.packet_writter_message = init_packet_writter_message()
        # This dict associates a dev_addr with a dict containing the {dev_eui, app_name and dev_name}
        self.devices_map = {}

    
    def connect(self):
        if self.mqtt_client:
            print('Existing connection')
        else:
            self.mqtt_client = mqtt.Client()
            self.mqtt_client.organization_id = self.organization_id
            self.mqtt_client.data_collector_id = self.data_collector_id
            self.mqtt_client.host = self.host
            self.mqtt_client.topics = self.topics
            self.mqtt_client.on_connect = on_connect
            self.mqtt_client.on_message = on_message
            self.mqtt_client.reconnect_delay_set(min_delay=10, max_delay=60)
            self.mqtt_client.connect_async(self.host, self.port, self.TIMEOUT)

            self.mqtt_client.prev_packet = self.prev_packet
            self.mqtt_client.packet_writter_message = self.packet_writter_message
            self.mqtt_client.devices_map = self.devices_map

            try:
                self.mqtt_client.loop_start()
            except KeyboardInterrupt:
                self.mqtt_client.disconnect()
                exit(0)

    def disconnect(self):
        self.mqtt_client.disconnect()
        self.mqtt_client = None

    def reconnect(self):
        print('reconnection')


def on_message(client, userdata, msg):
    
    try:
        # print("Topic %s Packet %s"%(msg.topic, msg.payload))
        # If message cannot, be decoded as json, skip it
        mqtt_messsage = json.loads(msg.payload.decode("utf-8"))

    except Exception as e:

        # First, check if we had a prev_packet. If so, first save it 
        if client.prev_packet is not None:
            client.packet_writter_message['packet'] = client.prev_packet

            save(client.packet_writter_message, client.data_collector_id)
            
            # Reset vars
            client.packet_writter_message = init_packet_writter_message()
            client.prev_packet = None

        # Save this message an topic into MQ
        client.packet_writter_message['messages'].append(
            {
                'topic':msg.topic,
                'message':msg.payload.decode("utf-8"),
                'data_collector_id': client.data_collector_id
            }
        )
        save(client.packet_writter_message, client.data_collector_id)

        # Reset packet_writter_message
        client.packet_writter_message = init_packet_writter_message()

        logging.debug('[SKIPPED] Topic: {0}. Message received: {1}'.format(msg.topic, msg.payload.decode("utf-8") ))
        return
    
    try:
        standard_packet = {}

        # If it's a Join message, then associate DevEUI with DevAddr
        if msg.topic[-5:]== "/join":
            device_info = { 'dev_eui': mqtt_messsage.get('devEUI', None)}
            client.devices_map[mqtt_messsage['devAddr']]= device_info

            # Save this message an topic into MQ
            client.packet_writter_message['messages'].append(
                {
                    'topic': msg.topic,
                    'message': msg.payload.decode("utf-8"),
                    'data_collector_id': client.data_collector_id
                }
            )
            save(client.packet_writter_message, client.data_collector_id)

            # Reset packet_writter_message
            client.packet_writter_message = init_packet_writter_message()

            logging.debug('Topic: {0}. Message received: {1}'.format(msg.topic, msg.payload.decode("utf-8")))

            return

        #From topic gateway/gw_id/tx or gateway/gw_id/tx
        search = re.search('gateway/(.*)?/*', msg.topic)
        if search is not None and ( search.group(0)[-2:] == "rx" or search.group(0)[-2:] == "tx"):

            if 'phyPayload' in mqtt_messsage:
                
                # PHYPayload shouldn't exceed 255 bytes by definition. In DB we support 300 bytes
                if len(mqtt_messsage['phyPayload']) > 300:
                    # Save this message an topic into MQ
                    client.packet_writter_message['messages'].append(
                        {
                            'topic': msg.topic,
                            'message': msg.payload.decode("utf-8"),
                            'data_collector_id': client.data_collector_id
                        }
                    )
                    save(client.packet_writter_message, client.data_collector_id)

                    # Reset packet_writter_message
                    client.packet_writter_message = init_packet_writter_message()

                    logging.debug('[SKIPPED] Topic: {0}. Message received: {1}'.format(msg.topic, msg.payload.decode("utf-8")))


                    return

                # Parse the base64 PHYPayload
                standard_packet = phy_parser.setPHYPayload(mqtt_messsage.get('phyPayload', None))
                # Save the PHYPayload
                standard_packet['data'] = mqtt_messsage.get('phyPayload', None)
            
            if search.group(0)[-2:] == 'rx':
                rx_info= mqtt_messsage.get('rxInfo', None)

                standard_packet['tmst'] = rx_info.get('timestamp', None)
                
                if rx_info.get('frequency') is not None:
                    standard_packet['freq'] = rx_info.get('frequency', None)/1000000

                standard_packet['chan'] = rx_info.get('channel', None)
                standard_packet['rfch'] = rx_info.get('rfChain', None)
                standard_packet['stat'] = rx_info.get('crcStatus', None)
                standard_packet['codr'] = rx_info.get('codeRate', None)
                standard_packet['rssi'] = rx_info.get('rssi', None)
                standard_packet['lsnr'] = rx_info.get('loRaSNR', None)
                standard_packet['size'] = rx_info.get('size', None)
                standard_packet['gateway'] = rx_info.get('mac', None)
            
                data_rate = rx_info.get('dataRate', None)
                standard_packet['modu'] = data_rate.get('modulation', None)
                standard_packet['datr'] = json.dumps({ "spread_factor": data_rate.get('spreadFactor', None), "bandwidth": data_rate.get('bandwidth', None)})

            elif search.group(0)[-2:] == 'tx':
                tx_info = mqtt_messsage.get('txInfo', None)

                standard_packet['tmst'] = tx_info.get('timestamp', None)
                
                if tx_info.get('frequency') is not None:
                    standard_packet['freq'] = tx_info.get('frequency', None)/1000000

                standard_packet['gateway'] = tx_info.get('mac', None)

                data_rate = tx_info.get('dataRate', None)
                standard_packet['modu'] = data_rate.get('modulation', None)
                standard_packet['datr'] = json.dumps({ "spread_factor": data_rate.get('spreadFactor', None), "bandwidth": data_rate.get('bandwidth', None)})
           
            # Add missing fields, independant from type of packet
            standard_packet['topic'] = msg.topic
            standard_packet['date'] = datetime.datetime.now().__str__() 
            standard_packet['data_collector_id'] = client.data_collector_id
            standard_packet['organization_id'] = client.organization_id

            # Save prev_packet in case is not empty
            if client.prev_packet is not None:
                client.packet_writter_message['packet']= client.prev_packet
                save(client.packet_writter_message, client.data_collector_id)
                
                # Reset variables
                client.prev_packet= None
                client.packet_writter_message = init_packet_writter_message()
            
            # Set the dev_eui and other information if available. Otherwise, save packet 
            if 'dev_addr' in standard_packet:
            
                if standard_packet['dev_addr'] in client.devices_map:
                    standard_packet['dev_eui'] = client.devices_map[standard_packet['dev_addr']]['dev_eui']
                    if len(client.devices_map[standard_packet['dev_addr']]) > 1:
                        standard_packet['app_name'] = client.devices_map[standard_packet['dev_addr']]['app_name']
                        standard_packet['dev_name'] = client.devices_map[standard_packet['dev_addr']]['dev_name']

                else:
                    # Save this packet for now
                    client.prev_packet = standard_packet
                    # Save the message and topic as well
                    client.packet_writter_message['messages'].append(
                        {
                            'topic': msg.topic,
                            'message': msg.payload.decode("utf-8"),
                            'data_collector_id': client.data_collector_id
                        }
                    )
            else:
                logging.debug('Unhandled situation')    
            
            logging.debug('Topic: {0}. Message received: {1}'.format(msg.topic, msg.payload.decode("utf-8")))

        # From topic application/*/device/*/rx or application/*/node/*/rx
        elif re.search('application/.*?/device/(.*)/rx', msg.topic) is not None or re.search('application/.*?/node/(.*)/rx', msg.topic) is not None:
            
            search = re.search('application/.*?/device/(.*)/rx', msg.topic)
            if search is None:
                search = re.search('application/.*?/node/(.*)/rx', msg.topic)
            
            if client.prev_packet is not None:            
                standard_packet = client.prev_packet
                client.prev_packet = None

                if standard_packet['f_count'] == mqtt_messsage.get('fCnt', None):
                    # Set location if given
                    if len(mqtt_messsage.get('rxInfo', None)) > 0:
                        location = mqtt_messsage.get('rxInfo', None)[0].get('location', None)
                        
                        if location: 
                            standard_packet['latitude'] = location.get('latitude', None)
                            standard_packet['longitude'] = location.get('longitude', None)
                            standard_packet['altitude'] = location.get('altitude', None)     

                    # Make sure we've matched the same device 
                    if 'dev_eui' in standard_packet and standard_packet['dev_eui'] is not None and standard_packet['dev_eui'] != search.group(1):
                        logging.warning("There's an error with LoraServerIODC logic")
                        exit(0)
                    
                    # Get dev_eui, app_name and dev_name from message
                    device_info = {'app_name': mqtt_messsage.get('applicationName', None), 'dev_name': mqtt_messsage.get('deviceName', None), 'dev_eui': mqtt_messsage.get('devEUI', None) }
                    client.devices_map[standard_packet['dev_addr']]= device_info

                    # Set previous values to current message
                    standard_packet['dev_eui'] = client.devices_map[standard_packet['dev_addr']]['dev_eui']
                    if len(client.devices_map[standard_packet['dev_addr']]) > 1:
                        standard_packet['app_name'] = client.devices_map[standard_packet['dev_addr']]['app_name']
                        standard_packet['dev_name'] = client.devices_map[standard_packet['dev_addr']]['dev_name']   
            
            logging.debug('Topic: {0}. Message received: {1}'.format(msg.topic, msg.payload.decode("utf-8")))

        else:
            logging.debug('[SKIPPED] Topic: {0}. Message received: {1}'.format(msg.topic, msg.payload.decode("utf-8") ))

            # First, check if we had a prev_packet. If so, first save it 
            if client.prev_packet is not None and len(standard_packet) == 0:
                client.packet_writter_message['packet'] = client.prev_packet
                save(client.packet_writter_message, client.data_collector_id)
                
                # Reset vars
                client.packet_writter_message = init_packet_writter_message()
                client.prev_packet = None

            # Save SKIPPED MQ message and topic
            client.packet_writter_message['messages'].append(
                {
                    'topic': msg.topic,
                    'message': msg.payload.decode("utf-8"),
                    'data_collector_id': client.data_collector_id
                }
            )
            save(client.packet_writter_message, client.data_collector_id)

            # Reset packet_writter_message
            client.packet_writter_message = init_packet_writter_message()

            return

        # Save packet
        if client.prev_packet is None and len(standard_packet) > 0:
            # Save packet JSON
            client.packet_writter_message['packet'] = standard_packet
            
            # Save MQ message and topic
            client.packet_writter_message['messages'].append(
                {
                    'topic': msg.topic,
                    'message': msg.payload.decode("utf-8"),
                    'data_collector_id': client.data_collector_id
                }
            )

            save(client.packet_writter_message, client.data_collector_id)            

            # Reset packet_writter_message obj
            packet_writter_message = init_packet_writter_message()

    except Exception as e:
        logging.error("Error creating Packet in LoraServerIOCollector:", e, "Topic: ", msg.topic, "Message: ", msg.payload.decode("utf-8"))  
        traceback.print_exc(file=sys.stdout)

def on_connect(client, userdata, flags, rc):
    logging.info("Connected to: {} with result code: {}".format(client.host, rc))
    client.subscribe(client.topics)

if __name__ == '__main__':
    from auditing.db.Models import DataCollector, DataCollectorType, Organization, commit, rollback

    print ("\n*****************************************************")
    print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
    print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
    print ("*****************************************************\n")

    parser = argparse.ArgumentParser(description='This script connects to a loraserver.io mqqt broker and saves messages into the DB.')

    requiredGroup = parser.add_argument_group('Required arguments')
    
    requiredGroup.add_argument('--ip',
                        help='MQTT broker ip, eg. --ip 192.168.3.101.')
    parser.add_argument('--port',
                        help='MQTT broker port, eg. --port 623. Default 1883.',
                        default= 1883,
                        type=int) 
    parser.add_argument('--collector-id',
                                help = 'The ID of the dataCollector. This ID will be associated to the packets saved into DB.')
    parser.add_argument('--organization-id',
                            help = 'The ID of the organization. This ID will be associated to the packets saved into DB.',
                            default= None)
    parser.add_argument('--topics',
                        nargs = '+',
                        help = 'List the topic(s) you want to suscribe separated by spaces. If nothing given, default will be "#.',
                        default = "#")

    options = parser.parse_args()

    if options.topics != None:
        topics = list()
        for topic in options.topics:
            topics.append((topic, 0))
    
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

        if options.ip and options.port:
            collector_type_obj = DataCollectorType.find_one_by_type("loraserverio_collector")

            if collector_type_obj is None:
                collector_type_obj= DataCollectorType(
                    type = "loraserverio_collector",
                    name= "loraserverio_collector")
                collector_type_obj.save()

            collector_obj= DataCollector.find_one_by_ip_port_and_dctype_id(collector_type_obj.id, options.ip, str(options.port))

            if collector_obj is None:
                collector_obj= DataCollector(
                    data_collector_type_id= collector_type_obj.id,
                    name= "Test collector",
                    organization_id = organization_obj.id,
                    ip= options.ip,
                    port= str(options.port))
                collector_obj.save()
        
        else:
            print('Datacollector IP and port must be provided if not provided a collector ID.')
            exit(0)

    connector = LoraServerIOCollector(
        data_collector_id = collector_obj.id,
        organization_id = collector_obj.organization_id,
        host = collector_obj.ip,
        port = int(collector_obj.port),
        ssl = None,
        user = None,
        password = None,
        topics = topics)

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