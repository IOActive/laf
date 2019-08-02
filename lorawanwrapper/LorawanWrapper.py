from ctypes import *
import os

dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, 'utils/lorawanWrapper.so')
lib = cdll.LoadLibrary(filename)
    

def printPHYPayload(phyPayload, key =  None):
    if isinstance(key, str) and len(key)>0 :
        key = bytes(key, encoding='utf-8')
    else:
        key = None
    
    lib.printPHYPayload.argtypes = [c_char_p, c_char_p]
    lib.printPHYPayload.restype = c_char_p

    try:
        return lib.printPHYPayload(bytes(phyPayload, encoding='utf-8'), key).decode('utf-8')
    except (AttributeError, TypeError) as e:
        return lib.printPHYPayload(phyPayload, key).decode('utf-8')

def testAppKeysWithJoinAccept(keys, data, dontGenerateKeys):
    keysArr = (c_char_p * len(keys))(*keys)

    if dontGenerateKeys:
        generateKeys = 0
    else:
        generateKeys = 1

    lib.testAppKeysWithJoinAccept.argtypes = [type(keysArr),  c_int, c_char_p, c_int]
    lib.testAppKeysWithJoinAccept.restype = c_char_p
    return lib.testAppKeysWithJoinAccept(keysArr, len(keysArr), bytes(data, encoding='utf-8'), generateKeys).decode('utf-8')

def testAppKeysWithJoinRequest(keys, data, dontGenerateKeys):
    keysArr = (c_char_p * len(keys))(*keys)

    if dontGenerateKeys:
        generateKeys = 0
    else:
        generateKeys = 1

    lib.testAppKeysWithJoinRequest.argtypes = [type(keysArr),  c_int, c_char_p, c_int]
    lib.testAppKeysWithJoinRequest.restype = c_char_p
    return lib.testAppKeysWithJoinRequest(keysArr, len(keysArr), bytes(data, encoding='utf-8'), generateKeys).decode('utf-8')

# Takes a JoinAccept and decypts it to retrieve the DevAddr
def getDevAddr(key, data):
    lib.getDevAddr.argtypes = [c_char_p, c_char_p]
    lib.getDevAddr.restype = c_char_p
    return lib.getDevAddr(bytes(key, encoding='utf-8'), bytes(data, encoding='utf-8')).decode('utf-8')

def getDevEUI(data):
    lib.getDevEUI.argtypes = [c_char_p]
    lib.getDevEUI.restype = c_char_p
    return lib.getDevEUI(bytes(data, encoding='utf-8')).decode('utf-8')

def getDevAddrFromMACPayload(data):
    lib.getDevAddrFromMACPayload.argtypes = [c_char_p]
    lib.getDevAddrFromMACPayload.restype = c_char_p
    return lib.getDevAddrFromMACPayload(bytes(data, encoding='utf-8')).decode('utf-8')

def generateSessionKeysFromJoins(joinRequest, joinAccept, appKey):
    lib.generateSessionKeysFromJoins.argtypes= [c_char_p, c_char_p, c_char_p]
    lib.generateSessionKeysFromJoins.restype= c_char_p
    return lib.generateSessionKeysFromJoins(bytes(joinRequest, encoding='utf-8'),bytes(joinAccept, encoding='utf-8'),bytes(appKey, encoding='utf-8')).decode('utf-8')

def getDevNonce(jr):
    lib.getDevNonce.argtypes = [c_char_p]
    lib.getDevNonce.restype = c_int
    return lib.getDevNonce(bytes(jr, encoding='utf-8'))

def getCounter(datapayload):
    lib.getCounter.argtypes = [c_char_p]
    lib.getCounter.restype = c_int
    return lib.getCounter(bytes(datapayload, encoding='utf-8'))

def generateValidMIC(data, key, jakey = None):
    if jakey is not None:
        jakey = bytes(jakey, encoding='utf-8')

    lib.generateValidMIC.argtypes = [c_char_p,c_char_p,c_char_p]
    lib.generateValidMIC.restype = c_char_p

    # If data is a string, return a string. If it's a bytearray, return a bytearray
    try:
        return lib.generateValidMIC(bytes(data, encoding='utf-8'), bytes(key, encoding='utf-8'), jakey).decode('utf-8')
    except (AttributeError, TypeError) as e:
        return lib.generateValidMIC(data, bytes(key, encoding='utf-8'), jakey)
    

def marshalJsonToPHYPayload(json, key = None, nwkskey= None):
    if key:
        key = bytes(key, encoding='utf-8')
    if nwkskey:
        nwkskey = bytes(nwkskey, encoding='utf-8')

    lib.marshalJsonToPHYPayload.argtypes = [c_char_p, c_char_p, c_char_p]
    lib.marshalJsonToPHYPayload.restype = c_char_p
    return lib.marshalJsonToPHYPayload(bytes(json, encoding='utf-8'), key, nwkskey).decode('utf-8')

def getMType(datapayload):
    lib.getMType.argtypes = [c_char_p]
    lib.getMType.restype = int
    return lib.getMType(bytes(datapayload, encoding='utf-8'))

def getMajor(datapayload):
    lib.getMajor.argtypes = [c_char_p]
    lib.getMajor.restype = int
    return lib.getMajor(bytes(datapayload, encoding='utf-8'))

def getJoinEUI(datapayload):
    lib.getJoinEUI.argtypes = [c_char_p]
    lib.getJoinEUI.restype = c_char_p
    return lib.getJoinEUI(bytes(datapayload, encoding='utf-8')).decode('utf-8')
