import re, datetime, os, sys, base64, json, logging, math
from auditing.db.Models import DevNonce, Gateway, Device, DeviceSession, GatewayToDevice, DataCollectorToDevice, GatewayToDeviceSession, DataCollectorToDeviceSession, Alert, Packet
from auditing.analyzers.utils import ReportAlert

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

# Dict containing (device_session_id:last_uplink_mic). Here it will be saved last uplink messages' MIC 
last_uplink_mic= {}

def processPacket(packet):
    gw_obj = None

    if packet.gateway is not None:
        gw_obj = Gateway.find_one_by_gw_hex_id_and_organization_id(packet.gateway, packet.organization_id)
        
        if gw_obj is None:
            try:
                gw_obj = Gateway(
                    gw_hex_id = packet.gateway,
                    location_latitude = packet.latitude,
                    location_longitude = packet.longitude,
                    data_collector_id = packet.data_collector_id,
                    organization_id = packet.organization_id
                )
                gw_obj.save()
            except Exception as exc:
                logging.error("Error trying to save Gateway: {0}".format(exc))

        gw_obj = updateLocation(gw_obj, packet)

    if packet.m_type == "JoinRequest":

        device_obj = Device.find_one_by_dev_eui_and_join_eui_and_datacollector_id(packet.dev_eui, packet.join_eui, packet.data_collector_id)

        if device_obj is None:

            device_obj = Device.find_one_by_dev_eui_and_join_eui_and_datacollector_id(packet.dev_eui, None, packet.data_collector_id) 

            if device_obj is None:
                
                try:
                    device_obj = Device(
                        dev_eui = packet.dev_eui,
                        join_eui = packet.join_eui,
                        organization_id = packet.organization_id,
                        )
                    device_obj.save()
                    
                except Exception as exc:
                    logging.error("Error trying to save Gateway: {0}".format(exc))
            
            else:
                # Add the JoinEUI
                device_obj.join_eui= packet.join_eui
        
        # Associate Device with a Gateway 
        if gw_obj is not None:            
            try:
                gateway_device_obj = GatewayToDevice.find_one_by_gateway_id_and_device_id(gw_obj.id, device_obj.id)
                if gateway_device_obj is None:
                    gateway_device_obj = GatewayToDevice(
                        gateway_id = gw_obj.id,
                        device_id = device_obj.id
                    )
                    gateway_device_obj.save()
            except Exception as exc:
                logging.error("Error trying to save GatewayToDevice: {0}".format(exc))    
        else:
            # If we don't receive the gateway in the packet,
            # get the hex ID of the gateway associated to the device if any. 
            # If we have more than 1 gateway associated to the device, this method returns None
            gw_obj= Gateway.find_only_one_gateway_by_device_id(device_obj.id)

        # Associate Device with the DataCollector if not previously existing
        device_data_collector_obj = DataCollectorToDevice.find_one_by_data_collector_id_and_device_id(packet.data_collector_id, device_obj.id)
        if device_data_collector_obj is None:
            
            try:
                device_data_collector_obj = DataCollectorToDevice(
                    data_collector_id = packet.data_collector_id,
                    device_id = device_obj.id
                )
                device_data_collector_obj.save()
            except Exception as exc:
                logging.error("Error trying to save DataCollectorToDevice from a JoinRequest: {0}".format(exc))

        # Check if DevNonce is repeated and save it
        prev_packet_id = DevNonce.saveIfNotExists(packet.dev_nonce, device_obj.id, packet.id) 
        if prev_packet_id and (device_obj.has_joined or device_obj.join_inferred):
            device_obj.repeated_dev_nonce = True

            parameters= {}
            parameters["dev_eui"]= device_obj.dev_eui
            parameters["dev_nonce"]= packet.dev_nonce
            parameters["prev_packet_id"]= prev_packet_id
            parameters['packet_date']= packet.date.strftime('%Y-%m-%d %H:%M:%S')
            
            if gw_obj:
                parameters["gateway"]= gw_obj.gw_hex_id
            else:
                parameters["gateway"]= "Unkwown"
            
            try:
                alert = Alert(
                    type = "LAF-001",
                    created_at = datetime.datetime.now(),
                    packet_id = packet.id,
                    device_id = device_obj.id,
                    parameters= json.dumps(parameters),
                    data_collector_id= packet.data_collector_id
                )
                alert.save()
                
                ReportAlert.print_alert(alert)
            except Exception as exc:
                logging.error("Error trying to save Alert LAF-001: {0}".format(exc))

        elif not(prev_packet_id):
            device_obj.has_joined=False
            device_obj.join_inferred=False

        device_obj.join_request_counter += 1
        device_obj.is_otaa = True

        # Save the first time it was seen
        if device_obj.first_up_timestamp is None:
            device_obj.first_up_timestamp = packet.date

        # Save the last time it was seen
        device_obj.last_up_timestamp = packet.date

        device_obj.last_packet_id= packet.id
    
    elif packet.m_type == "JoinAccept":
        
        # If the packet has a devEUI, increment the JoinAccept Counter in Device
        if packet.dev_eui is not None:
            devices = Device.find(packet.dev_eui, packet.data_collector_id)

            # Device with dev_eui exists an it's unique
            if len(devices) == 1:
                devices[0].join_accept_counter += 1
                devices[0].has_joined = True
            
            # Device with dev_eui doesn't exists. We must create the object (although we haven't the join_eui)
            elif len(devices) == 0:

                try:
                    device_obj = Device(
                    dev_eui = packet.dev_eui,
                    organization_id = packet.organization_id,
                    has_joined = True,
                    join_accept_counter = 1
                    )
                    device_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save Device from a JoinAccept: {0}".format(exc))

                try:
                    # Associate Device with the DataCollector
                    device_data_collector_obj = DataCollectorToDevice(
                        data_collector_id = packet.data_collector_id,
                        device_id = device_obj.id
                    )
                    device_data_collector_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save DataCollectorToDevice from a JoinAccept: {0}".format(exc))

            # We have more than one device. If the last packet received in that datacollector is a JoinReq, get the Device 
            elif len(devices) > 1:
                last_packet= Packet.find_previous_by_data_collector_and_dev_eui(packet.date, packet.data_collector_id, packet.dev_eui)

                if last_packet is not None and last_packet.m_type == "JoinRequest":
                    device_obj = Device.find_one_by_dev_eui_and_join_eui_and_datacollector_id(last_packet.dev_eui, last_packet.join_eui, packet.data_collector_id)
                    if device_obj is not None:
                        device_obj.join_accept_counter+= 1
                        device_obj.has_joined= True
                
                else:
                    logging.warning("Warning! Received a JoinAccept for a dev_eui shared by at least two devices")
        
        # If we don't know the deveui, check if the last packet received in that datacollector is a JoinReq
        else:
            last_packet= Packet.find_previous_by_data_collector_and_dev_eui(packet.date, packet.data_collector_id, None)
            
            if last_packet is not None and last_packet.m_type == "JoinRequest":
                    device_obj = Device.find_one_by_dev_eui_and_join_eui_and_datacollector_id(last_packet.dev_eui, last_packet.join_eui, packet.data_collector_id)
                    if device_obj is not None:
                        device_obj.join_accept_counter+= 1
                        device_obj.join_inferred= True


    # Case DataPacket
    elif packet.m_type == "UnconfirmedDataUp" or packet.m_type == "UnconfirmedDataDown" or packet.m_type == "ConfirmedDataUp" or packet.m_type == "ConfirmedDataDown": 
        
        dev_ses_obj = DeviceSession.find_one_by_dev_addr_and_datacollector_id(packet.dev_addr, packet.data_collector_id)
        if dev_ses_obj is None:
            try:
                dev_ses_obj = DeviceSession(
                    dev_addr = packet.dev_addr,
                    organization_id = packet.organization_id,
                    is_confirmed = (packet.m_type == "ConfirmedDataUp" or packet.m_type == "ConfirmedDataDown")
                )
                dev_ses_obj.save()
            except Exception as exc:
                logging.error("Error trying to save DeviceSession: {0}".format(exc))

        # In case we received the dev_eui, check if we have the Device in the database
        device_obj = None
        if packet.dev_eui is not None:
            devices = Device.find(packet.dev_eui, packet.data_collector_id)

            # Device with dev_eui exists an it's unique
            if len(devices) == 1:
                device_obj = devices[0]
            
            # Device with dev_eui doesn't exists. We must create the object (although we haven't the join_eui)
            elif len(devices) == 0:
                try:
                    device_obj = Device(
                    dev_eui = packet.dev_eui,
                    organization_id = packet.organization_id
                    )
                    device_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save Device from a Data packet: {0}".format(exc))

                # Associate Device with the DataCollector
                try:
                    device_data_collector_obj = DataCollectorToDevice(
                        data_collector_id = packet.data_collector_id,
                        device_id = device_obj.id
                    )
                    device_data_collector_obj.save()                    
                except Exception as exc:
                    logging.error("Error trying to save DataCollectorToDevice from a Data packet: {0}".format(exc))
            
            # We have more than one device. We can't do anything.
            elif len(devices) > 1:
                logging.warning("Warning! Received a DataPacket for a dev_eui shared by at least two devices")

        
        # Associate DeviceSession with a Gateway 
        if gw_obj is not None:
            gateway_device_session_obj = GatewayToDeviceSession.find_one_by_gateway_id_and_device_session_id(gw_obj.id, dev_ses_obj.id)
            if gateway_device_session_obj is None:
                try:
                    gateway_device_session_obj = GatewayToDeviceSession(
                        gateway_id = gw_obj.id,
                        device_session_id = dev_ses_obj.id
                    )
                    gateway_device_session_obj.save()
                except Exception as exc:
                    logging.error("Error trying to save GatewayToDeviceSession: {0}".format(exc))
        else:
            # If we don't receive the gateway in the packet,
            # get the hex ID of the gateway associated to the device_session if any. 
            # If we have more than 1 gateway associated to the device_session, this method returns None
            gw_obj= Gateway.find_only_one_gateway_by_device_session_id(dev_ses_obj.id)

        # Associate DeviceSession with the DataCollector
        device_session_data_collector_obj = DataCollectorToDeviceSession.find_one_by_data_collector_id_and_device_session_id(packet.data_collector_id, dev_ses_obj.id)
        if device_session_data_collector_obj is None:
            try:
                device_session_data_collector_obj = DataCollectorToDeviceSession(
                    data_collector_id = packet.data_collector_id,
                    device_session_id = dev_ses_obj.id
                )
                device_session_data_collector_obj.save()
            except Exception as exc:
                logging.error("Error trying to save DataCollectorToDeviceSession: {0}".format(exc))


        is_uplink_packet = (packet.m_type == "UnconfirmedDataUp" or packet.m_type == "ConfirmedDataUp")

        if is_uplink_packet:

            # Check counter
            if packet.f_count == 0:

                if dev_ses_obj.id in last_uplink_mic: # Make sure we have processed at least one packet for this device in this run before firing the alarm
                        
                    # Skip if received the same counter as previous packet and mics are equal
                    if not (packet.f_count == dev_ses_obj.getCounter(is_uplink_packet) and last_uplink_mic[dev_ses_obj.id] == packet.mic): 
                        
                        if device_obj is not None and device_obj.has_joined:
                            # The counter = 0  is valid, then change the has_joined flag
                            device_obj.has_joined = False

                        elif device_obj is not None and device_obj.join_inferred:
                            # The counter = 0  is valid, then change the join_inferred flag
                            device_obj.join_inferred = False
                        
                        else:
                            parameters= {}
                            parameters["dev_addr"]= dev_ses_obj.dev_addr
                            parameters["counter"]= dev_ses_obj.getCounter(is_uplink_packet)
                            parameters["new_counter"]= packet.f_count
                            parameters["prev_packet_id"]= dev_ses_obj.last_packet_id
                            parameters['packet_date']= packet.date.strftime('%Y-%m-%d %H:%M:%S')

                            if device_obj:
                                parameters['dev_eui']= device_obj.dev_eui
                            else:
                                parameters['dev_eui']= 'Unkwown'

                            if gw_obj:
                                parameters["gateway"]= gw_obj.gw_hex_id
                            else:
                                parameters["gateway"]= "Unkwown"
                            
                            try:
                                alert= Alert(
                                    type = "LAF-006",
                                    created_at = datetime.datetime.now(),
                                    packet_id = packet.id,
                                    device_session_id = dev_ses_obj.id,
                                    parameters= json.dumps(parameters),
                                    data_collector_id= packet.data_collector_id
                                )
                                alert.save()

                                ReportAlert.print_alert(alert)

                            except Exception as exc:
                                logging.error("Error trying to save Alert LAF-006: {0}".format(exc))

                            if device_obj is not None:
                                if not device_obj.is_otaa:
                                    dev_ses_obj.may_be_abp = True
                                else:
                                    logging.warning("Warning! The device is marked as OTAA but reset counter without having joined. Packet id %d"%(packet.id))

                        dev_ses_obj.reset_counter += 1
            
            elif packet.f_count <= dev_ses_obj.getCounter(is_uplink_packet):
                
                if dev_ses_obj.id in last_uplink_mic: # Make sure we have processed at least one packet for this device in this run before firing the alarm
                    
                    # Skip if received the same counter as previous packet and mics are equal
                    if not (packet.f_count == dev_ses_obj.getCounter(is_uplink_packet) and last_uplink_mic[dev_ses_obj.id] == packet.mic): 
                        parameters= {}
                        parameters["dev_addr"]= dev_ses_obj.dev_addr
                        parameters["counter"]= dev_ses_obj.getCounter(is_uplink_packet)
                        parameters["new_counter"]= packet.f_count
                        parameters["prev_packet_id"]= dev_ses_obj.last_packet_id
                        parameters['packet_date']= packet.date.strftime('%Y-%m-%d %H:%M:%S')

                        if device_obj:
                            parameters['dev_eui']= device_obj.dev_eui
                        else:
                            parameters['dev_eui']= 'Unkwown'

                        if gw_obj:
                            parameters["gateway"]= gw_obj.gw_hex_id
                        else:
                            parameters["gateway"]= "Unkwown"
                        
                        try:
                            alert= Alert(
                                type = "LAF-007",
                                created_at = datetime.datetime.now(),
                                packet_id = packet.id,
                                device_session_id= dev_ses_obj.id,
                                parameters= json.dumps(parameters),
                                data_collector_id= packet.data_collector_id
                            )
                            alert.save()

                            ReportAlert.print_alert(alert)

                        except Exception as exc:
                            logging.error("Error trying to save Alert LAF-007: {0}".format(exc))

        # Update the counter
        dev_ses_obj.setCounter(packet.f_count, is_uplink_packet)
        
        # Update total packet count
        dev_ses_obj.incrementPacketCounter(is_uplink_packet)
        
        # Keep track of the window time the DevAddr was on
        dev_ses_obj.updateUptime(packet.date, is_uplink_packet)

        if is_uplink_packet: # Save uplink MIC
            last_uplink_mic[dev_ses_obj.id]= packet.mic

        if device_obj is not None:                
            # Check if this DeviceSession hadn't previously a Device
            if dev_ses_obj.device_id is not None and device_obj.id != dev_ses_obj.device_id:
                conflict_device_obj = Device.find_one(dev_ses_obj.device_id)
                                
                parameters={}
                parameters["dev_eui"] = conflict_device_obj.dev_eui,
                parameters["new_dev_eui"] = device_obj.dev_eui,
                parameters["dev_addr"] = dev_ses_obj.dev_addr
                parameters["prev_packet_id"]= dev_ses_obj.last_packet_id
                parameters['packet_date']= packet.date.strftime('%Y-%m-%d %H:%M:%S')

                if gw_obj:
                    parameters["gateway"]= gw_obj.gw_hex_id
                else:
                    parameters["gateway"]= "Unkwown"
                
                try:
                    alert= Alert(
                        type = "LAF-002",
                        created_at = datetime.datetime.now(),
                        packet_id = packet.id,
                        device_id = device_obj.id,
                        device_session_id = dev_ses_obj.id,
                        parameters = json.dumps(parameters),
                        data_collector_id= packet.data_collector_id
                    )
                    alert.save()

                    ReportAlert.print_alert(alert)

                except Exception as exc:
                    logging.error("Error trying to save Alert LAF-002: {0}".format(exc))
            
            # device_obj.has_joined = False
            
            # Associate Device with DeviceSession
            dev_ses_obj.device_id = device_obj.id
        
        # Set the last packet id received for this device
        dev_ses_obj.setLastPacketId(is_uplink_packet, packet.id)

# The haversine formula determines the great-circle distance between two points on a sphere given their longitudes and latitudes.
def measure(lat1, lon1, lat2, lon2):
  R = 6378.137 #Radius of earth in KM
  dLat = lat2 * math.pi / 180 - lat1 * math.pi / 180
  dLon = lon2 * math.pi / 180 - lon1 * math.pi / 180
  a = math.sin(dLat/2) * math.sin(dLat/2) + math.cos(lat1 * math.pi / 180) * math.cos(lat2 * math.pi / 180) * math.sin(dLon/2) * math.sin(dLon/2)
  c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
  d = R * c
  return d * 1000 #meters

def updateLocation(gateway, packet):

    # This value can be changed for more/less accuracy
    location_accuracy = 20.0

    if packet.latitude is None or packet.longitude is None:
        return gateway
    else:
        lati = packet.latitude
        long = packet.longitude

    if gateway.location_latitude is None or gateway.location_longitude is None:
        gateway.location_latitude = lati
        gateway.location_longitude = long

    else:

        if measure(gateway.location_latitude, gateway.location_longitude, lati, long) > location_accuracy:
                    
            parameters={}
            parameters["gateway"]= gateway.gw_hex_id
            parameters["location_latitude"]= gateway.location_latitude
            parameters["location_longitude"]= gateway.location_longitude
            parameters["lati"]= lati
            parameters["long"]= long
            parameters['packet_date']= packet.date.strftime('%Y-%m-%d %H:%M:%S')

            try:
                alert= Alert(
                    type = "LAF-010",
                    created_at = datetime.datetime.now(),
                    packet_id = packet.id,
                    gateway_id = gateway.id,
                    parameters= json.dumps(parameters),
                    data_collector_id= packet.data_collector_id
                )
                alert.save()

                ReportAlert.print_alert(alert)
                
            except Exception as exc:
                logging.error("Error trying to save Alert LAF-010: {0}".format(exc))

        gateway.location_latitude = lati
        gateway.location_longitude = long

    return gateway