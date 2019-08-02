package main

import (
	"fmt"

	. "github.com/matiassequeira/lorawan"
)

func signPacket(dataPayload string, k string, jaK string) string {
	var key AES128Key
	var phy PHYPayload
	var jaKey AES128Key

	// These are dummy variables, not used but required by Go
	joinEUI := EUI64{0, 0, 0, 0, 0, 0, 0, 0}
	devNonce := DevNonce(0)

	if err := phy.UnmarshalText([]byte(dataPayload)); err != nil {
		fmt.Println("Unmarshall error with payload: ", dataPayload, err)
		return ""
	}

	if err := key.UnmarshalText([]byte(k)); err != nil {
		fmt.Println("Unmarshall error with key: ", k, err)
		return ""
	}

	if phy.MHDR.MType == JoinRequest {
		if err := phy.SetUplinkJoinMIC(key); err != nil {
			panic(err)
		}
	} else if phy.MHDR.MType == JoinAccept {
		// Unmarshal the previous key
		if err := jaKey.UnmarshalText([]byte(jaK)); err != nil {
			fmt.Println("Unmarshall error with JoinAccept Key: ", k, err)
			panic(err)
		}
		//Since the MIC is ecnrypted for JoinAccepts, it must be decrypted with the previous key before calculating the MIC and later encrypted with the new one.
		if err := phy.DecryptJoinAcceptPayload(jaKey); err != nil {
			panic(err)
		}
		if err := phy.SetDownlinkJoinMIC(JoinRequestType, joinEUI, devNonce, key); err != nil {
			fmt.Println("Make sure you provided the correct AppKey, used to sign this packet previously ")
			panic(err)
		}
		if err := phy.EncryptJoinAcceptPayload(key); err != nil {
			panic(err)
		}
	} else if phy.MHDR.MType == ConfirmedDataDown || phy.MHDR.MType == UnconfirmedDataDown {
		if err := phy.SetDownlinkDataMIC(LoRaWAN1_0, 0, key); err != nil {
			panic(err)
		}
	} else if phy.MHDR.MType == ConfirmedDataUp || phy.MHDR.MType == UnconfirmedDataUp {
		if err := phy.SetUplinkDataMIC(LoRaWAN1_0, 0, 0, 0, key, AES128Key{}); err != nil {
			panic(err)
		}
	}

	str, err := phy.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(str)

}
