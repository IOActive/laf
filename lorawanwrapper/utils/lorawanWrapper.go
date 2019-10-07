//lorawanWrapper.go

package main

import "C"

import (
	"bytes"
	"fmt"
	"os"
	"time"
	"unsafe"

	. "github.com/matiassequeira/lorawan"
	log "github.com/sirupsen/logrus"
)

//export marshalJsonToPHYPayload
func marshalJsonToPHYPayload(jsonPointer *C.char, keyPointer *C.char, nwkskeyPointer *C.char) *C.char {
	var jsonStr string = C.GoString(jsonPointer)
	var key string = C.GoString(keyPointer)
	var nwkskey string = C.GoString(nwkskeyPointer)
	b64 := parseJSONtoPHY(jsonStr, key, nwkskey)

	return C.CString(b64)
}

//export getJoinEUI
func getJoinEUI(dataPointer *C.char) *C.char {
	var dataBytes string = C.GoString(dataPointer)
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println(err)
		fmt.Println("Join request data: " + dataBytes)
		return C.CString("Error")
	}

	jrPL, ok := phy.MACPayload.(*JoinRequestPayload)
	if !ok {
		fmt.Println("MACPayload must be a *JoinRequestPayload")
		return C.CString("Error")
	}
	return C.CString(fmt.Sprintf("%v", jrPL.JoinEUI))

}

//export getMType
func getMType(dataPointer *C.char) C.int {
	var dataBytes string = C.GoString(dataPointer)
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println("Unmarshall error with PHYPayload trying to get MType")
		return -1
	}
	return C.int(phy.MHDR.MType)
}

//export getMajor
func getMajor(dataPointer *C.char) C.int {
	var dataBytes string = C.GoString(dataPointer)
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println("Unmarshall error with PHYPayload trying to get major")
		return -1
	}
	return C.int(phy.MHDR.Major)
}

//export getCounter
func getCounter(dataPointer *C.char) C.int {
	var dataBytes string = C.GoString(dataPointer)
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println("Unmarshall error with PHYPayload")
		return C.int(-1)
	}
	macPL, ok := phy.MACPayload.(*MACPayload)

	if ok {
		return C.int(macPL.FHDR.FCnt)
	} else {
		fmt.Println("Couldn't get counter")
		return C.int(-1)
	}

}

//export getDevNonce
func getDevNonce(dataPointer *C.char) C.int {
	var dataBytes string = C.GoString(dataPointer)
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println(err)
		fmt.Println("Join request data: " + dataBytes)
		return C.int(-1)
	}

	jrPL, ok := phy.MACPayload.(*JoinRequestPayload)
	if !ok {
		fmt.Println("MACPayload must be a *JoinRequestPayload")
		return C.int(-1)
	}

	//return C.CString(fmt.Sprintf("%v", jrPL.DevNonce))
	return C.int(jrPL.DevNonce)

}

//export generateSessionKeysFromJoins
func generateSessionKeysFromJoins(joinRequestPointer *C.char, JoinAcceptPointer *C.char, appKeyPointer *C.char) *C.char {
	var key AES128Key
	var joinEui EUI64
	var joinReq PHYPayload
	var joinAcc PHYPayload

	key.UnmarshalText([]byte(C.GoString(appKeyPointer)))

	if err := joinReq.UnmarshalText([]byte(C.GoString(joinRequestPointer))); err != nil {
		fmt.Println(err)
		return C.CString("")
	}
	jrPL, ok := joinReq.MACPayload.(*JoinRequestPayload)
	if !ok {
		fmt.Println("MACPayload must be a *JoinRequestPayload")
		return C.CString("")
	}

	if err := joinAcc.UnmarshalText([]byte(C.GoString(JoinAcceptPointer))); err != nil {
		fmt.Println(err)
		return C.CString("")
	}
	if err := joinAcc.DecryptJoinAcceptPayload(key); err != nil {
		fmt.Println("Error decrypting JoinAccept: ", err)
		return C.CString("")
	}
	jaPL, ok := joinAcc.MACPayload.(*JoinAcceptPayload)
	if !ok {
		fmt.Println("MACPayload must be a *JoinAcceptPayload")
		return C.CString("")
	}

	nwkSKey, err := getFNwkSIntKey(false, key, jaPL.HomeNetID, joinEui, jaPL.JoinNonce, jrPL.DevNonce)
	if err != nil {
		fmt.Println("Error when generating the NwkSKey ", err)
		return C.CString("")
	}
	appSkey, err := getAppSKey(false, key, jaPL.HomeNetID, joinEui, jaPL.JoinNonce, jrPL.DevNonce)
	if err != nil {
		fmt.Println("Error when generating the AppSKey: ", err)
		return C.CString("")
	}
	nKey, _ := nwkSKey.MarshalText()
	aKey, _ := appSkey.MarshalText()

	return C.CString(fmt.Sprintf("{\"nwkSKey\": \"%s\", \"appSKey\": \"%s\"}", string(nKey), string(aKey)))

}

//export getDevAddrFromMACPayload
func getDevAddrFromMACPayload(dataPointer *C.char) *C.char {
	var dataBytes string = C.GoString(dataPointer)
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println("Unmarshall error with PHYPayload")
		return C.CString("Error")
	}
	macPL, ok := phy.MACPayload.(*MACPayload)

	if ok {
		return C.CString(fmt.Sprintf("%v", macPL.FHDR.DevAddr))
	} else {
		fmt.Println("Couldn't get devAddr")
		return C.CString("")
	}

}

//export getDevAddr
func getDevAddr(appKeyPointer *C.char, dataPointer *C.char) *C.char {
	var dataBytes string = C.GoString(dataPointer)
	var key AES128Key
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println("Unmarshall error with PHYPayload")
		return C.CString("Error")
	}

	if err := key.UnmarshalText([]byte(C.GoString(appKeyPointer))); err != nil {
		fmt.Println("Unmarshall error with AppKey")
		return C.CString("Error")
	}

	if err := phy.DecryptJoinAcceptPayload(key); err != nil {
		fmt.Println("getDevAddr(): Error decrypting PHYPayload")
		return C.CString("Error")
	}

	jaPL, ok := phy.MACPayload.(*JoinAcceptPayload)

	if ok {
		return C.CString(fmt.Sprintf("%v", jaPL.DevAddr))

	}

	return C.CString("Error")

}

//export getDevEUI
func getDevEUI(dataPointer *C.char) *C.char {
	var dataBytes string = C.GoString(dataPointer)
	return C.CString(returnDevEUI(dataBytes))
}

//export generateValidMIC
func generateValidMIC(dataPointer *C.char, newKeyPointer *C.char, jaKeyPointer *C.char) *C.char {
	var dataBytes string = C.GoString(dataPointer)
	var newKey string = C.GoString(newKeyPointer)
	var jaKey string = C.GoString(jaKeyPointer)

	return C.CString(signPacket(dataBytes, newKey, jaKey))
}

func returnDevEUI(dataBytes string) string {
	var phy PHYPayload

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		fmt.Println(err)
		fmt.Println("Join request data: " + dataBytes)
		return ""
	}

	jrPL, ok := phy.MACPayload.(*JoinRequestPayload)
	if !ok {
		fmt.Println("MACPayload must be a *JoinRequestPayload")
		return "Error"
	}
	return fmt.Sprintf("%v", jrPL.DevEUI)
}

func reverseArray(array []byte) []byte {
	for i, j := 0, len(array)-1; i < j; i, j = i+1, j-1 {
		array[i], array[j] = array[j], array[i]
	}
	return array
}

//export testAppKeysWithJoinRequest
func testAppKeysWithJoinRequest(appKeysPointer **C.char, keysLen C.int, joinRequestDataPointer *C.char, generateKeys C.int) *C.char {
	var dataBytes string = C.GoString(joinRequestDataPointer)
	var phy PHYPayload
	var testCounter int64 = 0
	var key AES128Key
	var foundKeys string = ""

	setLogLevel()

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		log.Error("JoinRequest data: ", dataBytes, "Error: ", err)
		return C.CString(foundKeys)
	}

	/*********************************************************************
	Form possible keys using AppEUI+JoinEUI / JoinEUI/AppEUI combination
	********************************************************************/
	jrPL, ok := phy.MACPayload.(*JoinRequestPayload)
	if !ok {
		fmt.Println("MACPayload must be a *JoinRequestPayload")
		return C.CString("Error")
	}

	joinEUI, _ := jrPL.JoinEUI.MarshalBinary()
	devEUI, _ := jrPL.DevEUI.MarshalBinary()
	vendorsKeys := [][]byte{append(joinEUI, devEUI...), append(devEUI, joinEUI...)}

	log.Debug("DevEUI: ", devEUI, "AppEUI: ", joinEUI)

	for _, vendorKey := range vendorsKeys {
		if err := key.UnmarshalBinary(vendorKey); err != nil {
			log.Error("Unmarshall error with AppKey: ", vendorKey, err)
		}

		result, err := testAppKeyWithJoinRequest(key, phy, &testCounter)
		if err != nil {
			log.Error("Error with JoinRequest :", err)
			return C.CString(foundKeys)
		} else if len(result) > 0 {
			foundKeys += result + " "
		}
	}

	/********************************************************************
	Test keys given in keys file
	********************************************************************/
	length := int(keysLen)
	tmpslice := (*[1 << 30]*C.char)(unsafe.Pointer(appKeysPointer))[:length:length]
	for _, s := range tmpslice {
		element := C.GoString(s)

		if err := key.UnmarshalText([]byte(element)); err != nil {
			log.Error("Unmarshall error with AppKey: ", element, err)
		}

		result, err := testAppKeyWithJoinRequest(key, phy, &testCounter)
		if err != nil {
			log.Error("Error with JoinRequest :", err)
			return C.CString(foundKeys)
		} else if len(result) > 0 {
			foundKeys += result + " "
		}
	}

	if int(generateKeys) != 0 {

		start := time.Now()

		var i uint8
		var j uint8

		/********************************************************************
		Try with hashes MD5, SHA-1, SHA-2, SHA-3 of AppEUI, DevEUI, AppEUI+DevEUI and DevEUI+AppEUI. Truncate before and after 16 bytes
		********************************************************************/
		euisArray := [][]byte{joinEUI, devEUI, append(joinEUI, devEUI...), append(devEUI, joinEUI...)}
		cryptoHashes := generateHashes(euisArray)

		for _, hash := range cryptoHashes {
			if err := key.UnmarshalBinary(hash); err != nil {
				log.Error("Unmarshall error with AppKey: ", hash, err)
			}

			result, err := testAppKeyWithJoinRequest(key, phy, &testCounter)
			if err != nil {
				log.Error("Error with JoinRequest :", err)
				return C.CString(foundKeys)
			} else if len(result) > 0 {
				foundKeys += result + " "
			}
		}

		/********************************************************************
		Try with DevEUI[0] + AppEUI[0] + DevEUI[1] .., AppEUI[0] + DevEUI[0] + AppEUI[1] + .., and vice-versa
		********************************************************************/

		devEuiAppEui := make([]byte, 16, 16)
		devEuiAppEui[0], devEuiAppEui[2], devEuiAppEui[4], devEuiAppEui[6], devEuiAppEui[8], devEuiAppEui[10], devEuiAppEui[12], devEuiAppEui[14] = devEUI[0], devEUI[1], devEUI[2], devEUI[3], devEUI[4], devEUI[5], devEUI[6], devEUI[7]
		devEuiAppEui[1], devEuiAppEui[3], devEuiAppEui[5], devEuiAppEui[7], devEuiAppEui[9], devEuiAppEui[11], devEuiAppEui[13], devEuiAppEui[15] = joinEUI[0], joinEUI[1], joinEUI[2], joinEUI[3], joinEUI[4], joinEUI[5], joinEUI[6], joinEUI[7]

		appEuiDevEui := make([]byte, 16, 16)
		appEuiDevEui[0], appEuiDevEui[2], appEuiDevEui[4], appEuiDevEui[6], appEuiDevEui[8], appEuiDevEui[10], appEuiDevEui[12], appEuiDevEui[14] = joinEUI[0], joinEUI[1], joinEUI[2], joinEUI[3], joinEUI[4], joinEUI[5], joinEUI[6], joinEUI[7]
		appEuiDevEui[1], appEuiDevEui[3], appEuiDevEui[5], appEuiDevEui[7], appEuiDevEui[9], appEuiDevEui[11], appEuiDevEui[13], appEuiDevEui[15] = devEUI[0], devEUI[1], devEUI[2], devEUI[3], devEUI[4], devEUI[5], devEUI[6], devEUI[7]

		keysToTest := [][]byte{devEuiAppEui, appEuiDevEui, reverseArray(devEuiAppEui), reverseArray(appEuiDevEui)}

		for _, euiKey := range keysToTest {
			if err := key.UnmarshalBinary(euiKey); err != nil {
				log.Error("Unmarshall error with AppKey (DevEUI/AppEUI combination): ", euiKey, err)
			}

			result, err := testAppKeyWithJoinRequest(key, phy, &testCounter)
			if err != nil {
				log.Error("Error with JoinRequest :", err)
				return C.CString(foundKeys)
			} else if len(result) > 0 {
				foundKeys += result + " "
			}
		}

		/********************************************************************
		Try with the DevEUI or the AppEUI + 8 more repeated bytes. Do the same with these bytes at first
		********************************************************************/
		for i = 0; i <= 255; i++ {

			var repeatedBytes = []byte{i, i, i, i, i, i, i, i}

			euiKeys := [][]byte{append(joinEUI, repeatedBytes...), append(devEUI, repeatedBytes...), append(repeatedBytes, devEUI...), append(repeatedBytes, joinEUI...)}

			for _, euiKey := range euiKeys {
				if err := key.UnmarshalBinary(euiKey); err != nil {
					log.Error("Unmarshall error with AppKey (*EUI+bytes): ", euiKey, err)
				}

				result, err := testAppKeyWithJoinRequest(key, phy, &testCounter)
				if err != nil {
					log.Error("Error with JoinRequest :", err)
					return C.CString(foundKeys)
				} else if len(result) > 0 {
					foundKeys += result + " "
				}

			}

			if i == 255 {
				break
			}

		}

		/********************************************************************/
		// key1 variates the first byte and the last fifteeen bytes
		var key1 = make([]byte, 16, 16)

		// key2 variates even and odd bytes position equally
		var key2 = make([]byte, 16, 16)

		// key3 has the first 14 bytes in 0 and changes the last 2
		var key3 = make([]byte, 16, 16)
		key3[0], key3[1], key3[2], key3[3], key3[4], key3[5], key3[6], key3[7], key3[8], key3[9], key3[10], key3[11], key3[12], key3[13] = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		/********************************************************************/

		for i = 0; i <= 255; i++ {
			key1[0] = i
			key2[0], key2[2], key2[4], key2[6], key2[8], key2[10], key2[12], key2[14] = i, i, i, i, i, i, i, i
			key3[14] = i
			for j = 0; j <= 255; j++ {
				key1[2], key1[4], key1[6], key1[8], key1[10], key1[12], key1[14], key1[1], key1[3], key1[5], key1[7], key1[9], key1[11], key1[13], key1[15] = j, j, j, j, j, j, j, j, j, j, j, j, j, j, j
				key2[1], key2[3], key2[5], key2[7], key2[9], key2[11], key2[13], key2[15] = j, j, j, j, j, j, j, j
				key3[15] = j

				if err := key.UnmarshalBinary(key1); err != nil {
					log.Error("Unmarshall error with AppKey: ", key1, err)
				}

				// Testing key1
				result, err := testAppKeyWithJoinRequest(key, phy, &testCounter)
				if err != nil {
					log.Error("Error with JoinRequest with data: ", dataBytes, " Error: ", err)
					return C.CString(foundKeys)
				} else if len(result) > 0 {
					foundKeys += result + " "
				}

				if err := key.UnmarshalBinary(key2); err != nil {
					log.Error("Unmarshall error with AppKey: ", key2, err)
				}

				// Testing key2
				result, err = testAppKeyWithJoinRequest(key, phy, &testCounter)
				if err != nil {
					log.Error("Error with JoinRequest with data: ", dataBytes, " Error: ", err)
					return C.CString(foundKeys)
				} else if len(result) > 0 {
					foundKeys += result + " "
				}

				if err := key.UnmarshalBinary(key3); err != nil {
					log.Error("Unmarshall error with AppKey: ", key1, err)
				}

				// Testing key3
				result, err = testAppKeyWithJoinRequest(key, phy, &testCounter)
				if err != nil {
					log.Error("Error with JoinRequest with data: ", dataBytes, " Error: ", err)
					return C.CString(foundKeys)
				} else if len(result) > 0 {
					foundKeys += result + " "
				}

				// Added some breaks to avoid uint8 overflow
				if j == 255 {
					break
				}
			}
			if i == 255 {
				break
			}

		}

		elapsed := time.Since(start)

		log.Debug("Bruteforcing the JoinRequest took:", elapsed, ". Keys tested: ", testCounter)
	}

	if len(foundKeys) > 0 {
		return C.CString(foundKeys)
	} else {
		log.Debug("Key not found for JoinRequest with DevEui: ", returnDevEUI(dataBytes), " with data: ", dataBytes, " \n")
		return C.CString("")
	}

}

func testAppKeyWithJoinRequest(key AES128Key, phy PHYPayload, counter *int64) (string, error) {

	*counter++

	result, err := phy.ValidateUplinkJoinMIC(key)

	if err != nil {
		log.Error("Error validating JoinRequest MIC: ", err)
		return "", nil
	}

	if result {
		foundKey, _ := key.MarshalText()
		return string(foundKey), nil
	} else {
		return "", nil
	}

}

//export testAppKeysWithJoinAccept
func testAppKeysWithJoinAccept(appKeysPointer **C.char, keysLen C.int, joinAcceptDataPointer *C.char, generateKeys C.int) *C.char {
	var dataBytes string = C.GoString(joinAcceptDataPointer)
	var phy PHYPayload
	var key AES128Key
	var decryptCounter int64 = 0
	var foundKeys string = ""

	setLogLevel()

	if err := phy.UnmarshalText([]byte(dataBytes)); err != nil {
		log.Error("Error with Join accept with data: "+dataBytes, ". Error: ", err)
		return C.CString(foundKeys)
	}

	length := int(keysLen)
	tmpslice := (*[1 << 30]*C.char)(unsafe.Pointer(appKeysPointer))[:length:length]
	for _, s := range tmpslice {
		element := C.GoString(s)

		if err := key.UnmarshalText([]byte(element)); err != nil {
			log.Error("Unmarshall error with AppKey:", element, ".", err)
		}

		result, err := testAppKeyWithJoinAccept(key, phy, &decryptCounter)
		if err != nil {
			log.Error("Error with JoinAccept with data: ", dataBytes, " Error: ", err)
			return C.CString(foundKeys)
		} else if len(result) > 0 {
			foundKeys += result + " "
		}
	}

	if int(generateKeys) != 0 {
		start := time.Now()

		// key1 variates the first byte and the last fifteeen bytes
		var key1 = make([]byte, 16, 16)

		// key2 variates even and odd bytes position equally
		var key2 = make([]byte, 16, 16)

		// key3 has the first 14 bytes in 0 and changes the last 2
		var key3 = make([]byte, 16, 16)
		key3[0], key3[1], key3[2], key3[3], key3[4], key3[5], key3[6], key3[7], key3[8], key3[9], key3[10], key3[11], key3[12], key3[13] = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

		var i uint8
		var j uint8

		for i = 0; i <= 255; i++ {
			key1[0] = i
			key2[0], key2[2], key2[4], key2[6], key2[8], key2[10], key2[12], key2[14] = i, i, i, i, i, i, i, i
			key3[14] = i
			for j = 0; j <= 255; j++ {
				key1[2], key1[4], key1[6], key1[8], key1[10], key1[12], key1[14], key1[1], key1[3], key1[5], key1[7], key1[9], key1[11], key1[13], key1[15] = j, j, j, j, j, j, j, j, j, j, j, j, j, j, j
				key2[1], key2[3], key2[5], key2[7], key2[9], key2[11], key2[13], key2[15] = j, j, j, j, j, j, j, j
				key3[15] = j

				if err := key.UnmarshalBinary(key1); err != nil {
					log.Error("Unmarshall error with AppKey: ", key1, err)
				}

				// Testing key1
				result, err := testAppKeyWithJoinAccept(key, phy, &decryptCounter)
				if err != nil {
					log.Error("Error with JoinAccept with data: ", dataBytes, " Error: ", err)
					return C.CString(foundKeys)
				} else if len(result) > 0 {
					foundKeys += result + " "
				}

				if err := key.UnmarshalBinary(key2); err != nil {
					log.Error("Unmarshall error with AppKey: ", key2, err)
				}

				// Testing key2
				result, err = testAppKeyWithJoinAccept(key, phy, &decryptCounter)
				if err != nil {
					log.Error("Error with JoinAccept with data: ", dataBytes, " Error: ", err)
					return C.CString(foundKeys)
				} else if len(result) > 0 {
					foundKeys += result + " "
				}

				if err := key.UnmarshalBinary(key3); err != nil {
					log.Error("Unmarshall error with AppKey: ", key1, err)
				}

				// Testing key3
				result, err = testAppKeyWithJoinAccept(key, phy, &decryptCounter)
				if err != nil {
					log.Error("Error with JoinAccept with data: ", dataBytes, " Error: ", err)
					return C.CString(foundKeys)
				} else if len(result) > 0 {
					foundKeys += result + " "
				}

				// Added some breaks to avoid uint8 ovdrflow
				if j == 255 {
					break
				}
			}
			if i == 255 {
				break
			}
		}

		elapsed := time.Since(start)

		log.Debug("Bruteforcing the JoinAccept took:", elapsed)
	}

	if len(foundKeys) > 0 {
		return C.CString(foundKeys)
	} else {
		log.Debug("Key not found for JoinAccept with data: ", dataBytes, ". Keys tested: ", decryptCounter, " \n")
		return C.CString("")
	}
}

func testAppKeyWithJoinAccept(key AES128Key, phy PHYPayload, counter *int64) (string, error) {

	*counter++

	if err := phy.DecryptJoinAcceptPayload(key); err != nil {
		// Here we return nil instead of the error since this error is caused by a wrong key
		return "", nil
	}
	joinEUI := EUI64{8, 7, 6, 5, 4, 3, 2, 1}
	devNonce := DevNonce(258)

	result, err := phy.ValidateDownlinkJoinMIC(JoinRequestType, joinEUI, devNonce, key)

	if err != nil {
		// Here we return nil instead of the error since this error is caused by a wrong key
		//fmt.Println("Error validating Join MIC: ", err)
		return "", nil
	}

	if result == true {
		foundKey, _ := key.MarshalText()
		return string(foundKey), nil
	} else {
		return "", nil
	}
}

//export printPHYPayload
func printPHYPayload(phyPointer *C.char, keyPointer *C.char) *C.char {

	var buffer bytes.Buffer
	var phyBytes string = C.GoString(phyPointer)

	var key AES128Key
	var phy PHYPayload

	setLogLevel()

	if err := phy.UnmarshalText([]byte(phyBytes)); err != nil {
		log.Error("Unmarshal error with PHYPayload: ", phyBytes, " Error: ", err)
		return C.CString(fmt.Sprintln(""))
	}

	if keyPointer != nil {
		key.UnmarshalText([]byte(C.GoString(keyPointer)))

		if phy.MHDR.MType == UnconfirmedDataUp || phy.MHDR.MType == ConfirmedDataUp || phy.MHDR.MType == UnconfirmedDataDown || phy.MHDR.MType == ConfirmedDataDown {
			if err := phy.DecryptFRMPayload(key); err != nil {
				log.Error("Cannot decrypt FRMPayload:", err)
			}
		} else if phy.MHDR.MType == JoinAccept {
			if err := phy.DecryptJoinAcceptPayload(key); err != nil {
				log.Error("Cannot decrypt Join Accept:", err)
			}
		}

	}

	_, ok := phy.MACPayload.(*MACPayload)
	if ok {
		if err := phy.DecodeFOptsToMACCommands(); err != nil {
			log.Error("Error decoding FOpts:", err)
		}
	}

	phyJSON, err := phy.MarshalJSON()
	if err != nil {
		panic(err)
	}
	buffer.WriteString(fmt.Sprintf("%s", string(phyJSON)))

	return C.CString(buffer.String())
}

func setLogLevel() {
	if env := os.Getenv("ENVIRONMENT"); env == "PROD" {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
}

// TO BUILD THIS LIBRARY
//go build -o lorawanWrapper.so -buildmode=c-shared *.go

// DEPENDENCIES
//go get github.com/tidwall/sjson
//go get github.com/tidwall/gjson
//go get github.com/matiassequeira/lorawan
