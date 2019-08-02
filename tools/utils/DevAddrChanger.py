import re, base64

def changeAddress(udp, newAddress= None):

    if newAddress is not None:

        if len(newAddress) != 8:
            print("Received new address:", newAddress, ". Provide a 4 bytes address in hex")
            return udp

        #Invert the address to little endian format
        hexAddress = bytes([int(newAddress[6:],16)]) + bytes([int(newAddress[4:6],16)]) + bytes([int(newAddress[2:4],16)]) + bytes([int(newAddress[:2],16)])
        print("Hexaddr: ", hexAddress)

        search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', udp)

        if search is not None:
            decodedData=base64.b64decode(search.group(2))

            previousAddress= bytes([decodedData[4]]) + bytes([decodedData[3]]) + bytes([decodedData[2]]) + bytes([decodedData[1]])

            print ("Old address %r, New address %r"%(previousAddress, hexAddress))

            decodedData= decodedData[:1]+hexAddress + decodedData[5:]

            encodedData = base64.b64encode(decodedData)
            udp = search.group(1) + b'"data":"' + encodedData+ b'"' + search.group(3)
        
    return udp


