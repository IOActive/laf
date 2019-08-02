import json, datetime, logging, os
import lorawanwrapper.LorawanWrapper as LorawanWrapper 
from auditing.analyzers.utils import ReportAlert
from auditing.db.Models import Device, DeviceAuthData, DeviceSession, Alert, DataCollectorToDevice, DataCollectorToDeviceSession, PotentialAppKey

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

device_auth_obj = None
dontGenerateKeys = None
keys = None

def add(keyList, key):
    if len(keyList) == 0:
        return key
    elif key in keyList:
        return keyList
    else:
        return keyList + " "+ key

def bruteForce(packet):
    result = ""  
    global device_auth_obj  
    global dontGenerateKeys
    global keys
    device_auth_obj = None

    if packet.m_type == "JoinRequest":
        
        result = LorawanWrapper.testAppKeysWithJoinRequest(keys, packet.data, dontGenerateKeys)
        
        if result != "":

             # Check if Device exists. Otherwise, create it
            device_obj = Device.find_one_by_dev_eui_and_join_eui_and_datacollector_id(packet.dev_eui, packet.join_eui, packet.data_collector_id)
            if device_obj is None:
                try:
                    device_obj = Device(
                        dev_eui = packet.dev_eui,
                        join_eui = packet.join_eui,
                        organization_id = packet.organization_id,
                        )
                    device_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save Device: {0}".format(exc))

                # Associate Device with the DataCollector
                try:
                    device_data_collector_obj = DataCollectorToDevice(
                        data_collector_id = packet.data_collector_id,
                        device_id = device_obj.id
                    )
                    device_data_collector_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save DataCollectorToDevice: {0}".format(exc))

            # Check if the DeviceAuthData wasn't already generated
            device_auth_obj = DeviceAuthData.find_one_by_device_id(device_obj.id)
            if device_auth_obj is None:
                try:
                    device_auth_obj = DeviceAuthData(
                        device_id = device_obj.id,
                        data_collector_id = packet.data_collector_id,
                        organization_id = packet.organization_id,
                        join_request = packet.data,
                        created_at = datetime.datetime.now(), 
                        join_request_packet_id = packet.id
                        )
                    device_auth_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save DeviceAuthData at JoinRequest: {0}".format(exc))
            else:
                device_auth_obj.join_request_packet_id= packet.id
                device_auth_obj.join_request= packet.data


            # Split string possibly containing keys separated by spaces
            candidate_keys_array= result.split()

            for hex_key in candidate_keys_array:
                try:
                    potential_key_obj = PotentialAppKey(
                        app_key_hex = hex_key,
                        organization_id = packet.organization_id,
                        last_seen= packet.date,
                        packet_id= packet.id,
                        device_auth_data_id= device_auth_obj.id
                    )
                    potential_key_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save PotentialAppKey at JoinRequest: {0}".format(exc))           
    
    elif packet.m_type == "JoinAccept" and packet.data is not None:

        last_seconds_date = packet.date - datetime.timedelta(seconds=5)

        try:
            organization_keys= PotentialAppKey.find_all_by_organization_id_after_datetime(packet.organization_id, last_seconds_date)

            keys_array= list()
            for pk in organization_keys:
                # Fetch keys in byte format. Needed by ctypes
                keys_array.append(bytes(pk.app_key_hex.rstrip().upper(), encoding='utf-8')) 

            # Remove possible duplicates in array
            keys_array = list(dict.fromkeys(keys_array))

            result = LorawanWrapper.testAppKeysWithJoinAccept(keys_array, packet.data, True)
        except Exception as es:
            logging.error("Error trying to bforce JA:", es)

        if result != "":

            # Clean the key string
            result = result.rstrip().upper()
            
            for potential_key_obj in organization_keys:
                if potential_key_obj.app_key_hex == result:
                    device_auth_obj = DeviceAuthData.find_one_by_id(potential_key_obj.device_auth_data_id)

            # Get DevAddr from JA packet
            dev_addr = LorawanWrapper.getDevAddr(result, packet.data)

            # Check if DeviceSession exists. Otherwise, create it
            dev_ses_obj = DeviceSession.find_one_by_dev_addr_and_datacollector_id(dev_addr, packet.data_collector_id)
            if dev_ses_obj is None:
                try:
                    dev_ses_obj = DeviceSession(
                        dev_addr = dev_addr,
                        organization_id = packet.organization_id,
                    )
                    dev_ses_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save DeviceSession: {0}".format(exc))

                try:
                    device_session_data_collector_obj = DataCollectorToDeviceSession(
                    data_collector_id = packet.data_collector_id,
                    device_session_id = dev_ses_obj.id)
                    device_session_data_collector_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save DataCollectorToDeviceSession: {0}".format(exc))

            #Add missing data
            device_auth_obj.device_session_id = dev_ses_obj.id
            device_auth_obj.join_accept = packet.data
            device_auth_obj.join_accept_packet_id = packet.id
            
            # Add session keys
            device_auth_obj= deriveSessionKeys(device_auth_obj, result)

            # Get the device in order to get dev_eui
            device_obj= Device.find_one(device_auth_obj.device_id)

            parameters={}
            parameters["dev_addr"] = dev_ses_obj.dev_addr
            parameters["dev_eui"] = LorawanWrapper.getDevEUI(device_auth_obj.join_request)
            parameters["app_key"] = result
            parameters["join_request_packet_id"] = device_auth_obj.join_request_packet_id
            try:
                alert= Alert(
                    type = "LAF-009",
                    created_at = datetime.datetime.now(),
                    packet_id = packet.id,
                    device_session_id= dev_ses_obj.id,
                    device_auth_id= device_auth_obj.id,
                    parameters= json.dumps(parameters),
                    data_collector_id= packet.data_collector_id
                )
                alert.save()
            except Exception as exc:
                logging.error("Error trying to save Alert LAF-009: {0}".format(exc))     

            ReportAlert.print_alert(alert)

def deriveSessionKeys(device_auth_obj, appKey):
    json_result = LorawanWrapper.generateSessionKeysFromJoins(device_auth_obj.join_request, device_auth_obj.join_accept, appKey)
    keys= json.loads(json_result)
    device_auth_obj.apps_key = keys["appSKey"]
    device_auth_obj.nwks_key = keys["nwkSKey"]
    return device_auth_obj


def init(keysPath, notGenerateKeys):
    global keys
    keys = list()
    
    global dontGenerateKeys
    dontGenerateKeys = notGenerateKeys

    with open(keysPath) as f:
        for k in f:
            # Fetch keys in byte format. Needed by ctypes
            keys.append(bytes(k.rstrip().upper(), encoding='utf-8'))            


# JoinReq: AppEUI - DevEUI - DevNonce
# JoinAccept: AppNonce - NetID - DevAddr

# NwkSKey = aes128_encrypt(AppKey, 0x01 | AppNonce | NetID | DevNonce | pad16)
# AppSKey = aes128_encrypt(AppKey, 0x02 | AppNonce | NetID | DevNonce | pad16)