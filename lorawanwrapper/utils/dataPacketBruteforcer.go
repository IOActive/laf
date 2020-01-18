package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"math"
	"time"

	"github.com/jacobsa/crypto/cmac"
	log "github.com/sirupsen/logrus"
)

type SessionKeyData struct {
	AppNonce int
	DevNonce int
	NetID    string
	AppKey   string
}

func bruteforceNonces(appKey []byte, dataPacket []byte, netId []byte) []SessionKeyData {
	var possibleNonces []SessionKeyData
	var direction int
	b0 := make([]byte, 16)
	trials := 0.0
	var dN []byte
	var aN []byte
	var err error
	nwkSKey := make([]byte, 16)
	b := make([]byte, 16)

	setLogLevel()

	// log.Debug(fmt.Sprintln("Packet", dataPacket))
	// log.Debug(fmt.Sprintln("NetID", netId))
	// log.Debug(fmt.Sprintln("AppKey", appKey))

	// Init AES block
	block, err := aes.NewCipher(appKey[:])
	if err != nil {
		panic(err)
	}

	// Input block for NwkSKey
	b[0] = 0x01
	//NetID is not in LSB, rotate it
	b[4] = netId[2]
	b[5] = netId[1]
	b[6] = netId[0]
	b[9] = 0x00
	b[10] = 0x00
	b[11] = 0x00
	b[12] = 0x00
	b[13] = 0x00
	b[14] = 0x00
	b[15] = 0x00

	mhdr := dataPacket[0]
	mType := extractBits(int(mhdr), 3, 6)

	if mType == 2 || mType == 4 {
		direction = 0
	} else if mType == 3 || mType == 5 {
		direction = 1
	}

	devAddr := dataPacket[1:5]
	fCnt := dataPacket[6:8]

	msgLen := len(dataPacket) - 4

	// Input block for CMAC
	b0[0] = 0x49
	b0[1] = 0x00
	b0[2] = 0x00
	b0[3] = 0x00
	b0[4] = 0x00
	b0[5] = byte(direction)
	b0[6] = devAddr[0]
	b0[7] = devAddr[1]
	b0[8] = devAddr[2]
	b0[9] = devAddr[3]
	b0[10] = fCnt[0]
	b0[11] = fCnt[1]
	b0[12] = 0x0
	b0[13] = 0x0
	b0[14] = 0x0
	b0[15] = byte(msgLen)

	// Init input for CMAC
	input := append(b0, dataPacket[:msgLen]...)

	start := time.Now()

	for devNonce := 29478; devNonce < 0xffff; devNonce++ {

		if devNonce == 29480 {
			return nil
		}

		dN = []byte{byte((devNonce >> (8 * 0)) & 0xff), byte((devNonce >> (8 * 1)) & 0xff)}

		for appNonce := 7500140; appNonce < 0xffffff; appNonce++ {

			aN = []byte{byte((appNonce >> (8 * 0)) & 0xff), byte((appNonce >> (8 * 1)) & 0xff), byte((appNonce >> (8 * 2)) & 0xff)}

			// log.Debug(fmt.Sprintf("DevNonce %d, AppNonce %d", devNonce, appNonce))

			//Complete with Dynamic data: AppNonce and DevNonce
			//AppNonce is in LSB
			copy(b[1:4], aN)
			//DevNonce is in LSB
			copy(b[7:9], dN)

			// Compute NwkSKey
			block.Encrypt(nwkSKey[:], b)

			// Create CMAC block
			hash, err := cmac.New(nwkSKey[:])
			if err != nil {
				log.Error(err)
				panic(0)
			}

			// Write the payload to be hashed
			if _, err = hash.Write(input); err != nil {
				log.Error(err)
				panic(0)
			}

			// Compute CMAC
			cmacHash := hash.Sum([]byte{})

			// log.Debug(fmt.Sprintf("CMAC %+v", cmacHash))
			// log.Debug(fmt.Sprintf("MIC %+v", dataPacket[msgLen:]))

			// Check if MIC are equal
			res := bytes.Compare(dataPacket[msgLen:], cmacHash[0:4])
			if res == 0 {
				nonces := SessionKeyData{devNonce, appNonce, "", ""}
				possibleNonces = append(possibleNonces, nonces)
				log.Debug(fmt.Sprintf("MIC matched with AppNonce %d and DevNonce %d", appNonce, devNonce))
			}

			trials += 1

			if math.Mod(trials, 10000000) == 0 {
				elapsed := time.Since(start)
				log.Debug("Time elapsed", elapsed)
				start = time.Now()
			}
			// if appNonce == 7500148 {
			// 	return nil
			// }
		}
	}
	return possibleNonces
}

// Extract k bits given position p in numer
func extractBits(number int, k uint, p uint) int {

	return (((1 << k) - 1) & (number >> (p - 1)))

}
