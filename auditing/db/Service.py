from auditing.db.Models import Packet
import datetime, json
import dateutil.parser as dp

def save(jsonPacket):
	data = json.loads(jsonPacket)
	new_packet = Packet(
		date = dp.parse(data.get('date', None)),
		topic = data.get('topic', None),
		data_collector_id = data.get('data_collector_id', None),
		organization_id = data.get('organization_id', None),
		gateway = data.get('gateway', None),
		tmst = data.get('tmst', None),
		chan = data.get('chan', None),
		rfch = data.get('rfch', None),
		freq = data.get('freq', None),
		stat = data.get('stat', None),
		modu = data.get('modu', None),
		datr = data.get('datr', None),
		codr = data.get('codr', None),
		lsnr = data.get('lsnr', None),
		rssi = data.get('rssi', None),
		size = data.get('size', None),
		data = data.get('data', None),
		m_type = data.get('m_type', None),
		major = data.get('major', None),
		mic = data.get('mic', None),
		join_eui = data.get('join_eui', None),
		dev_eui = data.get('dev_eui', None),
		dev_nonce = data.get('dev_nonce', None),
		dev_addr = data.get('dev_addr', None),
		adr = data.get('adr', None),
		ack = data.get('ack', None),
		adr_ack_req = data.get('adr_ack_req', None),
		f_pending = data.get('f_pending', None),
		class_b = data.get('class_b', None),
		f_count = data.get('f_count', None),
		f_opts = data.get('f_opts', None),
		f_port = data.get('f_port', None),
		error = data.get('error', None),
		latitude = data.get('latitude', None),
		longitude = data.get('longitude', None),
		altitude = data.get('altitude', None),
		app_name = 	data.get('app_name', None),
		dev_name = 	data.get('dev_name', None),
	)
	new_packet.save_to_db()

def find_all(from_id, size):
	return Packet.find_all_from(from_id, size)