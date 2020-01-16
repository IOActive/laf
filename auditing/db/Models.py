from sqlalchemy import Column, DateTime, String, Integer, BigInteger, SmallInteger, Float, Boolean, ForeignKey, func, asc, desc, func, LargeBinary
from auditing.db import session, Base, engine
from sqlalchemy.dialects import postgresql, sqlite

BigIntegerType = BigInteger()
BigIntegerType = BigIntegerType.with_variant(postgresql.BIGINT(), 'postgresql')
BigIntegerType = BigIntegerType.with_variant(sqlite.INTEGER(), 'sqlite')

class AlertType(Base):
    __tablename__ = 'alert_type'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    code = Column(String(20), nullable=False, unique=True)
    name = Column(String(120), nullable=False)
    message = Column(String(4096), nullable=True) 
    risk = Column(String(20), nullable=False)
    description= Column(String(3000), nullable= False)

    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_one_by_code(cls, code):
        return session.query(cls).filter(cls.code == code).first()

class Alert(Base):
    __tablename__ = 'alert'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    type = Column(String(20), ForeignKey("alert_type.code"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=False)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=True)
    device_session_id = Column(BigIntegerType, ForeignKey("device_session.id"), nullable=True)
    gateway_id = Column(BigIntegerType, ForeignKey("gateway.id"), nullable=True)
    device_auth_id = Column(BigIntegerType, ForeignKey("device_auth_data.id"), nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    parameters = Column(String(4096), nullable=False)
    
    @classmethod
    def find_by_organization_id_and_created_at(cls, organization_id, since, until):
        return session.query(cls).filter(cls.packet_id == Packet.id).filter(DataCollector.id == Packet.data_collector_id).filter(DataCollector.organization_id == organization_id).filter(cls.created_at > since, cls.created_at < until).all()

    def save(self):
        session.add(self)
        session.flush()

class CollectorMessage(Base):
    __tablename__ = 'collector_message'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    message = Column(String(4096), nullable=True)
    topic = Column(String(512), nullable=True)

    def save(self):
        session.add(self)
        session.flush()

class Gateway(Base):
    __tablename__ = 'gateway'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    gw_hex_id = Column(String(16), nullable=True)
    location_latitude = Column(Float, nullable=True)
    location_longitude = Column(Float, nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_one(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def find_by_organization_id_and_created_at(cls, organization_id, since, until):
        return session.query(cls).filter(cls.packet_id == Packet.id).filter(DataCollector.id == Packet.data_collector_id).filter(DataCollector.organization_id == organization_id).filter(cls.created_at > since, cls.created_at < until).all()

    
    @classmethod
    def find_one_by_gw_hex_id_and_organization_id(cls, gw_hex_id, organization_id):
        return session.query(cls).filter(cls.gw_hex_id == gw_hex_id, cls.organization_id == organization_id).first()

    # This method tries to retrieve the gateway ID associated to a device. In case we have more than one, we return None
    @classmethod
    def find_only_one_gateway_by_device_id(cls, device_id):
        result= session.query(cls).join(GatewayToDevice).filter(GatewayToDevice.device_id == device_id).all()
        
        if len(result)== 1:
            return result[0]
        
        return None

    # This method tries to retrieve the gateway ID associated to a device session. In case we have more than one, we return None
    @classmethod
    def find_only_one_gateway_by_device_session_id(cls, device_session_id):
        result= session.query(cls).join(GatewayToDeviceSession).filter(GatewayToDeviceSession.device_session_id == device_session_id).all()

        if len(result)== 1:
            return result[0]
        
        return None
    
class DataCollector(Base):
    __tablename__ = "data_collector"
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    data_collector_type_id = Column(BigIntegerType, ForeignKey("data_collector_type.id"), nullable=False)
    name = Column(String(120), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=True)
    ip = Column(String(120), nullable=True)
    port = Column(String(120), nullable=True)
    user = Column(String(120), nullable=True)
    password = Column(LargeBinary, nullable=True)

    @classmethod
    def find_one_by_ip_port_and_dctype_id(cls, dctype_id, ip, port):
        return session.query(cls).filter(cls.ip == ip).filter(cls.data_collector_type_id == dctype_id).filter(cls.port == port).first()

    @classmethod
    def find_one_by_type_and_user_and_password_and_gateway_id(cls, dctype_id, user, password, id):
        return session.query(cls).filter(cls.user == user).filter(cls.data_collector_type_id == dctype_id).filter(cls.password == password).filter(cls.name == id).first()
    
    @classmethod
    def find_one_by_name_and_dctype_id(cls, dctype_id, name):
        return session.query(cls).filter(cls.data_collector_type_id == dctype_id, cls.name == name).first()

    @classmethod
    def find_one(cls, id=None):
        query = session.query(cls)
        if id:
            query = query.filter(cls.id == id)
        return query.first()

    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    def save(self):
        session.add(self)
        session.flush()
        commit()


class DataCollectorType(Base):
    __tablename__ = "data_collector_type"
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    type = Column(String(30), nullable=False, unique=True)
    name = Column(String(50), nullable=False)
    
    @classmethod
    def find_one_by_type(cls, type):
        return session.query(cls).filter(cls.type == type).first()

    @classmethod
    def find_type_by_id(cls, id):
        return session.query(cls).filter(cls.id == id).first().type

    def save(self):
        session.add(self)
        session.flush()

class Device(Base):
    __tablename__ = 'device'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    dev_eui = Column(String(16), nullable=False)
    join_eui = Column(String(16), nullable=True)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    first_up_timestamp = Column(DateTime(timezone=True), nullable=True)
    last_up_timestamp = Column(DateTime(timezone=True), nullable=True)
    repeated_dev_nonce = Column(Boolean, nullable=True)
    join_request_counter = Column(Integer, nullable=False, default=0)
    join_accept_counter = Column(Integer, nullable=False, default=0)
    has_joined = Column(Boolean, nullable=True, default = False)
    join_inferred = Column(Boolean, nullable=True, default = False)
    is_otaa = Column(Boolean, nullable=True)
    last_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_one(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def find_by_organization_id_and_last_up(cls, organization_id, since, until):
        return session.query(cls).filter(cls.organization_id == organization_id).filter(cls.last_up_timestamp > since, cls.last_up_timestamp < until).all()

    @classmethod
    def find_one_by_dev_eui_and_join_eui_and_datacollector_id(cls, dev_eui, join_eui, data_collector_id):
        query= session.query(cls).filter(cls.dev_eui == dev_eui, cls.join_eui == join_eui)
        query = query.filter(cls.id == DataCollectorToDevice.device_id).filter(DataCollectorToDevice.data_collector_id == data_collector_id)
        return query.first()

    @classmethod
    def find(cls, dev_eui, data_collector_id):
        query = session.query(cls)
        if data_collector_id:
            query = query.filter(cls.id == DataCollectorToDevice.device_id).filter(DataCollectorToDevice.data_collector_id == data_collector_id)
        if dev_eui:
            query = query.filter(cls.dev_eui == dev_eui)
        return query.all()

    
class DevNonce(Base):
    __tablename__ = 'dev_nonce'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    dev_nonce = Column(Integer, nullable=True)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=False)
    packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=False)

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def saveIfNotExists(cls, dev_nonce, device_id, packet_id):
        existing_dev_nonces = session.query(DevNonce).filter(DevNonce.dev_nonce == dev_nonce).filter(DevNonce.device_id == device_id).all()
        if len(existing_dev_nonces):
            prev_packet_id = existing_dev_nonces[0].packet_id
            existing_dev_nonces[0].packet_id = packet_id
            return prev_packet_id
        else:
            DevNonce(
                dev_nonce = dev_nonce,
                device_id = device_id,
                packet_id = packet_id
            ).save()
            session.flush()
            return None

    
class GatewayToDevice(Base):
    __tablename__ = 'gateway_to_device'
    gateway_id = Column(BigIntegerType, ForeignKey("gateway.id"), nullable=False, primary_key=True)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=False, primary_key=True)

    def save(self):
        session.add(self)
        session.flush()
    
    @classmethod
    def find_one_by_gateway_id_and_device_id(cls, gateway_id, device_id):
        return session.query(cls).filter(cls.device_id == device_id, cls.gateway_id == gateway_id).first()


class GatewayToDeviceSession(Base):
    __tablename__ = 'gateway_to_device_session'
    gateway_id = Column(BigIntegerType, ForeignKey("gateway.id"), nullable=False, primary_key=True)
    device_session_id = Column(BigIntegerType, ForeignKey("device_session.id"), nullable=False, primary_key=True)

    def save(self):
        session.add(self)
        session.flush()
    
    @classmethod
    def find_one_by_gateway_id_and_device_session_id(cls, gateway_id, device_session_id):
        return session.query(cls).filter(cls.device_session_id == device_session_id, cls.gateway_id == gateway_id).first()


class DeviceSession(Base):
    __tablename__ = 'device_session'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    may_be_abp = Column(Boolean, nullable=True)
    reset_counter = Column(Integer, nullable=False, default=0)
    is_confirmed = Column(Boolean, nullable=True)
    dev_addr = Column(String(8), nullable=False)
    up_link_counter = Column(Integer, nullable=False, default=-1)
    down_link_counter = Column(Integer, nullable=False, default=-1)
    max_down_counter = Column(Integer, nullable=False, default=-1)
    max_up_counter = Column(Integer, nullable=False, default=-1)
    total_down_link_packets = Column(BigIntegerType, nullable=False, default=0)
    total_up_link_packets = Column(BigIntegerType, nullable=False, default=0)
    first_down_timestamp = Column(DateTime(timezone=True), nullable=True)
    first_up_timestamp = Column(DateTime(timezone=True), nullable=True)
    last_down_timestamp = Column(DateTime(timezone=True), nullable=True)
    last_up_timestamp = Column(DateTime(timezone=True), nullable=True)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=True)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    device_auth_data_id = Column(BigIntegerType, ForeignKey("device_auth_data.id"), nullable=True)
    last_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)


    def setCounter(self, new_counter, uplink):
        if uplink:
            self.up_link_counter = new_counter
            self.max_up_counter = max(self.max_up_counter,new_counter)
        else:
            self.downLinkCounter = new_counter
            self.max_down_counter = max(self.max_down_counter, new_counter)

    def getCounter(self,uplink):
        if uplink:
            return self.up_link_counter
        else:
            return self.down_link_counter

    def incrementPacketCounter(self, uplink):
        if uplink:
            self.total_up_link_packets += 1
        else:
            self.total_down_link_packets += 1

    def setLastPacketId(self, uplink, id):
        if uplink:
            self.last_packet_id = id

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_one(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def find(cls, dev_eui, join_eui, organization_id):
        query = session.query(cls)
        if organization_id:
            query = query.filter(cls.organization_id == organization_id)
        if join_eui:
            query = query.filter(cls.device_id == Device.id).filter(Device.join_eui == join_eui)
        if dev_eui:
            query = query.filter(cls.device_id == Device.id).filter(Device.dev_eui == dev_eui)
        return query.all()

    def updateUptime(self, timestamp, uplink):
        if uplink:
            if self.first_up_timestamp is None:
                self.first_up_timestamp = timestamp
            else:
                self.last_up_timestamp = timestamp
        else:
            if self.first_down_timestamp is None:
                self.first_down_timestamp = timestamp
            else:
                self.last_down_timestamp = timestamp

    @classmethod
    def find_one_by_dev_addr_and_datacollector_id(cls, dev_addr, data_collector_id):
        query = session.query(cls).filter(cls.dev_addr == dev_addr)
       
        query = query.join(DataCollectorToDeviceSession).filter(DataCollectorToDeviceSession.data_collector_id == data_collector_id)

        return query.first()


class Packet(Base):
    __tablename__ = 'packet'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    date = Column(DateTime(timezone=True), nullable=False)
    topic = Column(String(256), nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    gateway = Column(String(16), nullable=True)
    tmst = Column(BigIntegerType, nullable=True)
    chan = Column(SmallInteger, nullable=True)
    rfch = Column(Integer, nullable=True)
    seqn = Column(Integer, nullable=True)
    opts = Column(String(20), nullable=True)
    port = Column(Integer, nullable=True)
    freq = Column(Float, nullable=True)
    stat = Column(SmallInteger, nullable=True)
    modu = Column(String(4), nullable=True)
    datr = Column(String(50), nullable=True)
    codr = Column(String(10), nullable=True)
    lsnr = Column(Float, nullable=True)
    rssi = Column(Integer, nullable=True)
    size = Column(Integer, nullable=True)
    data = Column(String(300), nullable=True)
    m_type = Column(String(20), nullable=True)
    major = Column(String(10), nullable=True)
    mic = Column(String(8), nullable=True)
    join_eui = Column(String(16), nullable=True)
    dev_eui = Column(String(16), nullable=True)
    dev_nonce = Column(Integer, nullable=True)
    dev_addr = Column(String(8), nullable=True)
    adr = Column(Boolean, nullable=True)
    ack = Column(Boolean, nullable=True)
    adr_ack_req = Column(Boolean, nullable=True)
    f_pending = Column(Boolean, nullable=True)
    class_b = Column(Boolean, nullable=True)
    f_count = Column(Integer, nullable=True)
    f_opts = Column(String(500), nullable=True)
    f_port = Column(Integer, nullable=True)
    error = Column(String(300), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    altitude = Column(Float, nullable=True)
    app_name = Column(String(100), nullable=True)
    dev_name = Column(String(100), nullable=True)

    def to_json(self):
        return {
            'id': self.id,
            'date': "{}".format(self.date),
            'topic': self.topic,
            'data_collector_id': self.data_collector_id,
            'organization_id': self.organization_id,
            'gateway': self.gateway,
            'tmst': self.tmst,
            'chan': self.chan,
            'rfch': self.rfch,
            'seqn': self.seqn,
            'opts': self.opts,
            'port': self.port,
            'freq': self.freq,
            'stat': self.stat,
            'modu': self.modu,
            'datr': self.datr,
            'codr': self.codr,
            'lsnr': self.lsnr,
            'rssi': self.rssi,
            'size': self.size,
            'data': self.data,
            'm_type': self.m_type,
            'major': self.major,
            'mic': self.mic,
            'join_eui': self.join_eui,
            'dev_eui': self.dev_eui,
            'dev_nonce': self.dev_nonce,
            'dev_addr': self.dev_addr,
            'adr': self.adr,
            'ack': self.ack,
            'adr_ack_req': self.adr_ack_req,
            'f_pending': self.f_pending,
            'class_b': self.class_b,
            'f_count': self.f_count,
            'f_opts': self.f_opts,
            'f_port': self.f_port,
            'error': self.error
        }

    @classmethod
    def find_by_organization_id_and_date(cls, organization_id, since, until):
        return session.query(cls).filter(cls.organization_id == organization_id).filter(cls.date > since, cls.date < until).all()

    @classmethod
    def find_by_organization_id_and_mtype_and_date(cls, organization_id, mtype, since, until):
        return session.query(cls).filter(cls.organization_id == organization_id).filter(cls.date > since, cls.date < until, cls.m_type == mtype).all()

    @classmethod
    def find_all_from(cls, id, size = 1000):
    	return session.query(Packet).filter(Packet.id >= id).order_by(asc(Packet.id)).limit(size).all()

    @classmethod
    def find_previous_by_data_collector_and_dev_eui(cls, date, data_collector_id, dev_eui = None):
        previous_date = session.query(func.max(Packet.date)).filter(Packet.date < date).filter(Packet.data_collector_id == data_collector_id).filter(Packet.dev_eui == dev_eui).scalar()
        return session.query(Packet).filter(Packet.date == previous_date).filter(Packet.data_collector_id == data_collector_id).filter(Packet.dev_eui == dev_eui).first()

    @classmethod
    def rows_quantity(cls):
        return session.query(func.max(cls.id)).scalar() 

    def save_to_db(self):
        session.add(self)
        session.flush()

class DeviceAuthData(Base):
    __tablename__ = 'device_auth_data'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    join_request = Column(String(200), nullable=True)
    join_accept = Column(String(200), nullable=True)
    apps_key = Column(String(32), nullable=True)
    nwks_key = Column(String(32), nullable=True)
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=False)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=True)
    device_session_id = Column(BigIntegerType, ForeignKey("device_session.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    join_accept_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    join_request_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    app_key_hex = Column(String(32), nullable=True)
    # These vars are in case we cracked the key using another JoinRequest
    second_join_request_packet_id = Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    second_join_request = Column(String(200), nullable=True)

    def save(self):
        session.add(self)
        session.flush()

    def is_complete(self):
        return self.join_request is not None and self.join_accept is not None
    
    @classmethod
    def find_one_by_device_id(cls, device_id):
        return session.query(cls).filter(cls.device_id == device_id).first()

    @classmethod
    def find_one_by_id(cls, id):
        return session.query(cls).filter(cls.id==id).first()

class PotentialAppKey(Base):
    __tablename__= 'potential_app_key'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    device_auth_data_id= Column(BigIntegerType, ForeignKey("device_auth_data.id"), nullable=False)
    app_key_hex = Column(String(32), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    packet_id= Column(BigIntegerType, ForeignKey("packet.id"), nullable=True)
    organization_id = Column(BigIntegerType, ForeignKey("organization.id"), nullable=True)

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_all_by_organization_id_after_datetime(cls, organization_id, since):
        return session.query(cls).filter(cls.organization_id == organization_id, cls.last_seen > since).order_by(desc(cls.last_seen)).all()
    
    @classmethod
    def find_all_by_device_auth_id(cls, dev_auth_data_id):
        return session.query(cls).filter(cls.device_auth_data_id == dev_auth_data_id).all()

class RowProcessed(Base):
    __tablename__ = 'row_processed'
    id = Column(BigIntegerType, primary_key=True, autoincrement=True)
    last_row = Column(Integer, nullable=False, default=0)
    analyzer = Column(String(20), nullable=False)

    def save(self):
        session.add(self)
    
    @classmethod
    def find_one(cls, id):
        return session.query(cls).filter(cls.id == id).first()

    @classmethod
    def find_one_by_analyzer(cls, analyzer_id):
        return session.query(cls).filter(cls.analyzer == analyzer_id).first()

    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    def save_and_flush(self):
        session.add(self)
        session.flush()


class DataCollectorToDevice(Base):
    __tablename__ = 'data_collector_to_device'
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False, primary_key=True)
    device_id = Column(BigIntegerType, ForeignKey("device.id"), nullable=False, primary_key=True)

    def save(self):
        session.add(self)
        session.flush()

    @classmethod
    def find_one_by_data_collector_id_and_device_id(cls, data_collector_id, device_id):
        return session.query(cls).filter(cls.data_collector_id == data_collector_id, cls.device_id == device_id).first()

class DataCollectorToDeviceSession(Base):
    __tablename__ = 'data_collector_to_device_session'
    data_collector_id = Column(BigIntegerType, ForeignKey("data_collector.id"), nullable=False, primary_key=True)
    device_session_id = Column(BigIntegerType, ForeignKey("device_session.id"), nullable=False, primary_key=True)

    def save(self):
        session.add(self)
        session.flush()
    
    @classmethod
    def find_one_by_data_collector_id_and_device_session_id(cls, data_collector_id, device_session_id):
        return session.query(cls).filter(cls.data_collector_id == data_collector_id, cls.device_session_id == device_session_id).first()

class Organization(Base):
    __tablename__ = "organization"
    id = Column(BigIntegerType, primary_key=True)
    name = Column(String(120), unique=True)

    @classmethod
    def find_one(cls, id=None):
        query = session.query(cls)
        if id:
            query = query.filter(cls.id == id)
        return query.first()

    @classmethod
    def count(cls):
        return session.query(func.count(cls.id)).scalar()

    def save(self):
        session.add(self)
        session.flush()
        commit()

def commit():
    session.commit()

def begin():
    session.begin()

def rollback():
    session.rollback()

 
Base.metadata.create_all(engine)
