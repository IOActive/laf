import re, base64, struct

def changeFCnt(udp, newCounter=None):
    
    if newCounter is None:
        return udp

    if newCounter < 0 or newCounter > 65535:
        print("Provide a 2 bytes int")
        return udp

    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)
    if search is not None:
        decodedData=base64.b64decode(search.group(2))

        # Check if packet is actually a data packet
        m_type= decodedData[0]&0xE0
        if m_type != 0x40 and m_type != 0x60 and m_type != 0x80 and m_type != 0xA0:
            print("Cannot change fCnt in a non-data packet")
            return udp  
        
        # Save previous counter
        old_counter = decodedData[6:8]

        # Convert new_counter to byte and form the new bytearray
        decodedData= decodedData[:6] + struct.pack('<H', newCounter) + decodedData[8:]

        new_cntr = decodedData[6:8]
        
        print ("Old FCnt %d, New FCnt %d"%(struct.unpack('<H',old_counter)[0], struct.unpack('<H',new_cntr)[0]))

        encodedData = base64.b64encode(decodedData)
        udp= search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    else:
        print("Data field not found in packet")
    
    return udp
        