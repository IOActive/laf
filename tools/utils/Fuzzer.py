import random, datetime, base64,re, itertools, struct

# fuzzmode is a list of the desired modes
def fuzz(data, fuzzModes):

    if fuzzModes is None:
        return data

    for mode in fuzzModes:
        if mode == 1:
            data = fuzzPhyPayload(data)
        elif mode == 2:
            data = fuzzDecodedPHYPayload(data)
        elif mode == 3:
            data = duplicateDataField(data)
        elif mode == 4:
            data = fuzzMIC(data)
        elif mode == 5:
            data = fuzzFCnt(data)
        elif mode == 6:
            data=fuzzFRMPayload(data)
        elif mode == 7:
            data = fuzzMType(data)
        elif mode == 8:
            data = fuzzFPort(data)
        elif mode == 9:
            data = fuzzDevNonce(data)
        elif mode == 10:
            data = fuzzDevEui(data)
        else:   
            print("Fuzzing mode incorrect")
    return data

# Option 1
def fuzzPhyPayload(udp):
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    if search is not None:
        data=search.group(2)
        #data = insertRandomData(data,random.randrange(1,len(data)), random.randrange(1,100))
        data = changeByte(data,random.randrange(1,len(data)), random.randrange(0,256))
        return search.group(1) + b'"data":"' + data + b'"' + search.group(3)
    else:
        return udp

# Option 2
def fuzzDecodedPHYPayload(udp):
    
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        decodedData=changeByte(decodedData, random.randrange(1,len(decodedData)), random.randrange(0,256))
        #decodedData=repeatByte(decodedData, random.randrange(1,len(decodedData)), random.randrange(0,256) )
        encodedData = base64.b64encode(decodedData)
        return search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    else:
        return udp

# Option 3 
def duplicateDataField(udp): 
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"}]}', udp)
    if search is not None:
        return search.group(1) + b'"data":"' + search.group(2) + b'","data":"' + search.group(2) + b'"}]}'
    else:
        return udp      

# Option 4
def fuzzMIC(udp): 
    #The MIC is composed by the last 4 octects
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        posToFuzz= len(decodedData) - random.randrange(0,4) 
        print ("Fuzzing MIC position %d out of %d"%(posToFuzz, len(decodedData)))
        decodedData= changeByte(decodedData, posToFuzz, random.randrange(0,256))
        encodedData = base64.b64encode(decodedData)
        return search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    else:
        return udp

# Option 5
def fuzzFCnt(udp):
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        counter = decodedData[6:8]
        decodedData = changeByte(decodedData, 6 + random.randrange(0,2) +1, random.randrange(0,256))
        #decodedData = decodedData[:6] + chr(0) + chr(0) + decodedData[8:]
        fuzzedCounter = decodedData[6:8]
        print ("Old FCnt %d, New FCnt %d"%(struct.unpack('<H',counter)[0], struct.unpack('<H',fuzzedCounter)[0]))

        encodedData = base64.b64encode(decodedData)
        return search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    else:
        return udp

# Option 6
def fuzzFRMPayload(udp):
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        #When FRMPayload is present, FPort is present. This function considers an empty FOpts is empty, then MHDR+FHDR+FPort is 9 bytes.
        #So, MACPayload is 9 bytes (MHDR+FHDR+FPort) + FRMPayload + 4 bytes (MIC)
        decodedData = changeByte(decodedData, random.randrange(10,len(decodedData)-4), random.randrange(0,256))
        encodedData = base64.b64encode(decodedData)
        return search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    else:
        return udp

# Option 7 
def fuzzMType(udp):
    # The MType is in the first 3 bits of the first MACPayload byte
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    mTypesNumber = [0, 32, 64, 96, 128, 160, 192, 224]
    mTypesDescription = {
        0x00:"Join Request", 
        0x20:"Join Accept", 
        0x40:"Unconfirmed Data Up", 
        0x60:"Unconfirmed Data Down", 
        0x80:"Confirmed Data Up", 
        0xA0:"Confirmed Data Down", 
        0xC0:"RFU", 
        0xE0:"Proprietary"
        }

    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        previousMtype= decodedData[0]&0xE0

        #XOR MType bits with a random MType 
        decodedData = bytes([decodedData[0] ^ mTypesNumber[random.randrange(0,8)]]) + decodedData[1:]
        
        newMType= decodedData[0] & 0xE0

        print ("Previous MType= %s. New MType= %s"%(mTypesDescription[previousMtype],mTypesDescription[newMType]))

        encodedData = base64.b64encode(decodedData)

        return search.group(1) + b'"data":"' + encodedData+ b'"' + search.group(3)
    else:
        return udp


# Option 8
def fuzzFPort(udp):
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        decodedData = changeByte(decodedData, 8 + 1, random.randrange(0,256))
        encodedData = base64.b64encode(decodedData)
        return search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    else:
        return udp

# Option 9
def fuzzDevNonce(udp):
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        m_type= decodedData[0] & 0xE0
        if m_type == 0x00: # JoinRequest
            decodedData = changeByte(decodedData, 16 + 1 + random.randrange(0,2), random.randrange(0,256))
            encodedData = base64.b64encode(decodedData)
            return search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    return udp

# Option 10 
def fuzzDevEui(udp):
    search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)
    if search is not None:
        decodedData=base64.b64decode(search.group(2))
        m_type= decodedData[0] & 0xE0
        if m_type == 0x00: # JoinRequest
            decodedData = changeByte(decodedData, 8 + 1 + random.randrange(0,8), random.randrange(0,256))
            encodedData = base64.b64encode(decodedData)
            return search.group(1) + b'"data":"' + encodedData + b'"' + search.group(3)
    return udp

#Aux functions
def changeByte(buf, pos, val):
    
    print ("%s:\nReplacing byte offset=%d, old value=%r, new=%r"%(str(datetime.datetime.now()), pos-1, buf[pos-1], val))
    
    buf = buf[:pos-1] + bytes([val]) + buf[pos:]

    return buf

def repeatByte(buf, pos, cant):
    print ("%s:\nRepeating byte offset=%d, value=%r, cant=%i"%(str(datetime.datetime.now()), pos-1, buf[pos-1], cant))
    buf = buf[:pos-1] + buf[pos-1]*cant + buf[pos:]
    return buf

def insertRandomData(buf, pos, cant): 

    randomString = ""
    for _ in itertools.repeat(None, cant):
        randomString+=chr(random.randrange(0,256))
    print ("%s:\nInserted after byte offset=0x%d random data %s"%(str(datetime.datetime.now()), pos-1, randomString))

    buf = buf[:pos-1] + buf[pos-1] + bytes(randomString, encoding='utf-8') + buf[pos:]

    return buf