from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

# ---> Comment these lines
if "ENVIRONMENT" not in os.environ:
    DB_HOST = "localhost"
    DB_NAME = "loraguard_db"
    DB_USERNAME = "postgres"
    DB_PASSWORD = "postgres" 
    DB_PORT = 5432
    os.environ["ENVIRONMENT"] = "DEV"

else:
    DB_HOST = os.environ["DB_HOST"] 
    DB_NAME = os.environ["DB_NAME"] 
    DB_USERNAME = os.environ["DB_USERNAME"] 
    DB_PASSWORD = os.environ["DB_PASSWORD"] 
    DB_PORT = os.environ["DB_PORT"] 

engine = create_engine('postgresql+psycopg2://{user}:{pw}@{url}:{port}/{db}'.format(user=DB_USERNAME, pw=DB_PASSWORD, url=DB_HOST, port= DB_PORT, db=DB_NAME))
# If you'd like to use sqlite <---


# Uncomment these lines if you want to work with sqlite instead of postgres
# engine = create_engine('sqlite:///orm_in_detail.sqlite')
# os.environ["ENVIRONMENT"] = "DEV"

Base = declarative_base()
sessionBuilder = sessionmaker()
sessionBuilder.configure(bind=engine)
session = sessionBuilder()

from auditing.db.Models import AlertType, RowProcessed, rollback, commit
import logging

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

try:
    if AlertType.count() == 0:
        AlertType(code= 'LAF-001', name= 'DevNonce repeated', risk= 'LOW', message='DevNonce {dev_nonce} repeated for DevEUI {dev_eui}. Previous packet {prev_packet_id}, current packet {packet_id}. Data collector {collector.name}.', description="DevNonces for each device should be random enough to not collide. If the same DevNonce was repeated in many messages, it can be inferred that a device is under a replay attack. This is, an attacker who captured a JoinRequest and is trying to send it again to the gateway." ).save()
        AlertType(code= 'LAF-002', name= 'DevEUIs sharing the same DevAddr', risk= 'INFO', description= "Two different devices might have been assigned the same DevAddr. This isn't a security threat, but it shouldn't happen since the lorawan server wouldn't be able to distinguish in which device a message is generated.").save()
        AlertType(code= 'LAF-003', name= 'Join replay', risk= 'MEDIUM', description= 'A duplicated JoinRequest message was detected. The LoRaWAN network may be under a join replay attack.').save()
        AlertType(code= 'LAF-004', name= 'Uplink data packets replay', risk= 'MEDIUM', description= 'A duplicated uplink packet was detected, which may imply that the lorawan server is under a replay attack. This is, an attacker that may have captured an uplink packet (sent from the device) and is sending it again to the lorawan server.').save()
        AlertType(code= 'LAF-006', name= 'Possible ABP device (counter reset and no join)', risk= 'HIGH', description= "If the counter was reset (came back to 0), the DevAddr is kept the same, and no previous Join process was detected, may imply that the device is activated by personalization (ABP). ABP devices implementation is discouraged because no join process is done, which means that session keys are kept the same forever. A device that doesn't change its session keys is prone to different attacks such as eaveasdrop or replay.", message= "DevAddr {dev_addr} counter was reset. Previous counter was {counter} and received {new_counter}. This device may be ABP or device is not rejoining a counter overflow. Previous packet {prev_packet_id}, current packet {packet_id}. Data collector {collector.name}.").save() 
        AlertType(code= 'LAF-007', name= 'Received smaller counter for DevAddr  (distinct from 0)', risk= 'INFO', description= "If an attacker obtains a pair of session keys (for having stolen the AppKey in OTAA devices or the AppSKey/NwkSKey in ABP devices), he/she would be able to send fake valid data to the server. For the server to accept spoofed messages, it is required for the FCnt (Frame Counter) of the message to be higher than the FCnt of the last message sent. In an scenario where the original spoofed device keeps sending messages, the server would start to discard (valid) messages since they would have a smaller FCnt. Hence, when messages with a smaller FCnt value than expected by the lorawan server are being received, it is possible to infer that a parallel session was established.", message= "Received smaller counter for DevAddr {dev_addr}. Previous counter was {counter} and current {new_counter}. Previous packet {prev_packet_id}, current packet {packet_id}. Data collector {collector.name}.").save() 
        AlertType(code= 'LAF-009', name= 'Password cracked', risk= 'HIGH', description= "The AppKey of the device was found trying with a well-known or nonrandom string. It was decrypted using a pair of join messages (Request and Accept).", message="Key {app_key} found for device {dev_eui} with devaddr {dev_addr}. Matched JoinRequest packet {join_request_packet_id}. JoinAccept packet {packet_id}. Data Collector {collector.name}").save() 
        AlertType(code= 'LAF-010', name= 'Gateway changed location', risk= 'MEDIUM', description= "If the gateway is not supposed to change its location. It may have been stolen, moved, or a fake gateway may be trying to impersonate the legitimate Gateway.", message= "Gateway {gw_hex_id} may have been moved. Previous latitude {location_latitude}. Current latitute {lati}. Previous longitude {location_longitude}. Current longitude {long}. Current packet {packet_id}. Data collector {collector.name}.").save()
        commit()

    if RowProcessed.count() == 0:
        RowProcessed(last_row= 0, analyzer= 'bruteforcer').save_and_flush()
        RowProcessed(last_row= 0, analyzer= 'packet_analyzer').save_and_flush()
        RowProcessed(last_row= 0, analyzer= 'printer').save_and_flush()
        commit()

except Exception as exc:
    logging.error('Error at commit when initializing:', exc)
    logging.info('Rolling back the session')
    rollback()