from auditing.db.Models import Packet, CollectorMessage
import datetime, json
import dateutil.parser as dp

def save(jsonPacket):
	
	# Parse the JSON into a dict
	data = json.loads(jsonPacket)

	# print('Saving {0}'.format(jsonPacket))

	# If a packet was received, persist it 
	new_packet = None
	packet_dict= data.get('packet')
	if packet_dict:
		new_packet = Packet(
			date = dp.parse( packet_dict.get('date', None)),
			topic = packet_dict.get('topic', None),
			data_collector_id = packet_dict.get('data_collector_id', None),
			organization_id = packet_dict.get('organization_id', None),
			gateway = packet_dict.get('gateway', None),
			tmst = packet_dict.get('tmst', None),
			chan = packet_dict.get('chan', None),
			rfch = packet_dict.get('rfch', None),
			freq = packet_dict.get('freq', None),
			stat = packet_dict.get('stat', None),
			modu = packet_dict.get('modu', None),
			datr = packet_dict.get('datr', None),
			codr = packet_dict.get('codr', None),
			lsnr = packet_dict.get('lsnr', None),
			rssi = packet_dict.get('rssi', None),
			size = packet_dict.get('size', None),
			data = packet_dict.get('data', None),
			m_type = packet_dict.get('m_type', None),
			major = packet_dict.get('major', None),
			mic = packet_dict.get('mic', None),
			join_eui = packet_dict.get('join_eui', None),
			dev_eui = packet_dict.get('dev_eui', None),
			dev_nonce = packet_dict.get('dev_nonce', None),
			dev_addr = packet_dict.get('dev_addr', None),
			adr = packet_dict.get('adr', None),
			ack = packet_dict.get('ack', None),
			adr_ack_req = packet_dict.get('adr_ack_req', None),
			f_pending = packet_dict.get('f_pending', None),
			class_b = packet_dict.get('class_b', None),
			f_count = packet_dict.get('f_count', None),
			f_opts = packet_dict.get('f_opts', None),
			f_port = packet_dict.get('f_port', None),
			error = packet_dict.get('error', None),
			latitude = packet_dict.get('latitude', None),
			longitude = packet_dict.get('longitude', None),
			altitude = packet_dict.get('altitude', None),
			app_name = packet_dict.get('app_name', None),
			dev_name = packet_dict.get('dev_name', None)
		)
		new_packet.save_to_db()

	# Save the message/s 
	messages= data.get('messages')
	for message in messages:
		collector_message = CollectorMessage(
			data_collector_id = message.get('data_collector_id'),
			message = message.get('message'),
			topic = message.get('topic')
		)
		
		# In case a packet was instantiated, relate it with the message
		if new_packet:
			collector_message.packet_id=new_packet.id

		collector_message.save()

	if len(messages) == 0:
		raise Exception("No messages received for packet {0}".format(jsonPacket))


def find_all(from_id, size):
	return Packet.find_all_from(from_id, size)