# LoRaWAN Security Framework - GenericMqttCollector
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

class GenericMqttCollector:
    
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
        # The data sent to the MQTT queue, to be written by the packet writer. It must have at least one MQ message
        self.packet_writter_message = init_packet_writter_message()
    
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

            self.mqtt_client.self.packet_writter_message = self.packet_writter_message

            self.mqtt_client.reconnect_delay_set(min_delay=10, max_delay=60)
            self.mqtt_client.connect_async(self.host, self.port, self.TIMEOUT)

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
        payload = msg.payload.decode("utf-8") 
        standardPacket = {}

        # Save this message an topic into MQ
        client.packet_writter_message['messages'].append(
            {
                'topic':msg.topic,
                'message':msg.payload.decode("utf-8"),
                'data_collector_id': client.data_collector_id
            }
        )

        if len(payload) > 0:
            mqttMessage = json.loads(payload)

            if 'data' not in mqttMessage:
                logging.error('Received a message without "data" field. Topic: %s. Message: %s'%(msg.topic, payload))
                return 

            # Pad the base64 string till it is a multiple of 4
            mqttMessage['data'] += "=" * ((4 - len(mqttMessage['data']) % 4) % 4)
            # Parse the base64 PHYPayload
            standardPacket = phy_parser.setPHYPayload(mqttMessage['data'])
            
            standardPacket['chan'] = mqttMessage.get('chan', None)
            standardPacket['stat'] = mqttMessage.get('stat', None)
            standardPacket['lsnr'] = mqttMessage.get('lsnr', None)
            standardPacket['rssi'] = mqttMessage.get('rssi', None)
            standardPacket['tmst'] = mqttMessage.get('tmst', None)
            standardPacket['rfch'] = mqttMessage.get('rfch', None)
            standardPacket['freq'] = mqttMessage.get('freq', None)
            standardPacket['modu'] = mqttMessage.get('modu', None)
            standardPacket['datr'] = json.dumps(parse_datr(mqttMessage.get('datr', None)))
            standardPacket['codr'] = mqttMessage.get('codr', None)
            standardPacket['size'] = mqttMessage.get('size', None)
            standardPacket['data'] = mqttMessage.get('data', None)
            
            # Gateway not provided by this broker
            standardPacket['gateway'] = None

            # These fields come in the /up topic
            standardPacket['seqn'] = mqttMessage.get('seqn', None)
            standardPacket['opts'] = mqttMessage.get('opts', None)
            standardPacket['port'] = mqttMessage.get('port', None)

        # These fields are indepedant from the payload
        standardPacket['topic'] = msg.topic
        if "/joined" in msg.topic:
            standardPacket['m_type'] = "JoinAccept"
        standardPacket['date'] = datetime.datetime.now().__str__() 
        standardPacket['dev_eui'] = getDevEUIFromMQTTTopic(msg.topic)
        standardPacket['data_collector_id'] = client.data_collector_id
        standardPacket['organization_id'] = client.organization_id

        client.packet_writter_message['packet']= standardPacket

        save(client.packet_writter_message, client.data_collector_id)
        
        logging.debug('Topic: {0}. Message received: {1}'.format(msg.topic, msg.payload.decode("utf-8") ))

        # Reset packet_writter_message
        client.packet_writter_message = init_packet_writter_message()

    except Exception as e:
        logging.error("Error creating Packet in GenericMqttCollector:", e, "Topic: ", msg.topic, "Message: ", msg.payload.decode("utf-8"))  

def on_connect(client, userdata, flags, rc):
    logging.info("Connected to: {} with result code: {}".format(client.host, rc))
    client.subscribe(client.topics)

def getDevEUIFromMQTTTopic(topic):
    search = re.search('lora/(.*)/', topic)
    devEUI= None
    if search:
        devEUI = search.group(1).replace('-', '')
    return devEUI

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

    parser = argparse.ArgumentParser(description='This script connects to the mqqt broker and saves messages into the DB. You must specify a unique collectorID and you can specify the topics you want to suscribe to.')

    requiredGroup = parser.add_argument_group('Required arguments')
    requiredGroup.add_argument('--ip',
                        help='MQTT broker ip, eg. --ip 192.168.3.101.')
    requiredGroup.add_argument('--port',
                        help='MQTT broker port, eg. --port 623.',
                        type=int) 
    parser.add_argument('--collector-id',
                                help = 'The ID of the dataCollector. This ID will be associated to the packets saved into DB. eg. --id 1')
    parser.add_argument('--organization-id',
                            help = 'The ID of the dataCollector. This ID will be associated to the packets saved into DB. eg. --id 1',
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
            collector_type_obj = DataCollectorType.find_one_by_type("generic_collector")

            if collector_type_obj is None:
                collector_type_obj= DataCollectorType(
                    type = "generic_collector",
                    name= "generic_collector")
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

    connector = GenericMqttCollector(
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