package main

import (
	"C"
	"encoding/json"
	"fmt"

	. "github.com/matiassequeira/lorawan"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// TEST MESSAGES

// {"mhdr":{"mType":"JoinRequest","major":"LoRaWANR1"},"macPayload":{"joinEUI":"55d239ac716f234d","devEUI":"b827eb891cf50003","devNonce":51639},"mic":"7005c4a5"}
// {"mhdr":{"mType":"JoinAccept","major":"LoRaWANR1"},"macPayload":{"bytes":"HWxw2bAlEDfZF8xu"},"mic":"fc1ede82"}

// {"mhdr":{"mType":"UnconfirmedDataUp","major":"LoRaWANR1"},"macPayload":{"fhdr":{"devAddr":"017fc1c4","fCtrl":{"adr":true,"adrAckReq":false,"ack":false,"fPending":false,"classB":false},"fCnt":17,"fOpts":[{"cid":"LinkADRReq","payload":{"channelMaskAck":true,"dataRateAck":false,"powerAck":true}}]},"fPort":93,"frmPayload":[{"bytes":"/2EyELe4m4F5txMSp93Gi+Od7uT0wI/xFFPlKA=="}]},"mic":"7934d552"}

// {"mhdr":{"mType":"UnconfirmedDataDown","major":"LoRaWANR1"},"macPayload":{"fhdr":{"devAddr":"017fc1c4","fCtrl":{"adr":true,"adrAckReq":false,"ack":false,"fPending":false,"classB":false},"fCnt":55,"fOpts":[{"cid":"LinkADRReq","payload":{"dataRate":2,"txPower":4,"chMask":[true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true],"redundancy":{"chMaskCntl":0,"nbRep":1}}}]},"fPort":null,"frmPayload":null},"mic":"be4d8cbf"}

func parseJSONtoPHY(jsonPHY string, key string, nwkskey string) string {
	type phyAlias *PHYPayload
	phy := PHYPayload{}
	var is_data_packet bool
	var is_uplink bool
	var fOpts []Payload
	is_decrypted_join_accept := false
	is_decrypted_data_packet := false

	setLogLevel()

	switch major := gjson.Get(jsonPHY, "mhdr.major"); major.String() {
	case "LoRaWANR1":
		jsonPHY, _ = sjson.Set(jsonPHY, "mhdr.major", 0)
	default:
		panic("Error: major not recognized")
	}

	mType := gjson.Get(jsonPHY, "mhdr.mType").String()
	switch mType {
	case "JoinRequest":
		jsonPHY, _ = sjson.Set(jsonPHY, "mhdr.mType", 0)
		phy.MACPayload = &JoinRequestPayload{}
	case "JoinAccept":
		jsonPHY, _ = sjson.Set(jsonPHY, "mhdr.mType", 1)

		// If macPayload.bytes was given, it means the JoinAccept data is encrypted. We don't need the AppKey in this case
		if gjson.Get(jsonPHY, "macPayload.bytes").Exists() {
			if key != "" {
				log.Debug("AppKey is not needed because the JoinAccept is already encrypted. Note that the MIC won't be re-generated. If you'd like to provide a modified JoinAccept, use the following format: \n{\"mhdr\":{\"mType\":\"JoinAccept\",\"major\":\"LoRaWANR1\"},\"macPayload\":{\"joinNonce\":11,\"homeNetID\":\"000000\",\"devAddr\":\"AABBCCDD\",\"dlSettings\":\"08\",\"rxDelay\":1,\"cFlist\":null},\"mic\":\"CCDDEEFF\"}")
			}
			phy.MACPayload = &DataPayload{}
		} else {
			if key == "" {
				panic("AppKey must be provided in order to encrypt JoinAccept and generate its MIC.")
			} else {
				log.Debug("Received a decrypted JoinAccept and its AppKey. The MIC will be re-generated.")
				phy.MACPayload = &JoinAcceptPayload{}
				is_decrypted_join_accept = true
			}
		}

	case "UnconfirmedDataUp":
		jsonPHY, _ = sjson.Set(jsonPHY, "mhdr.mType", 2)
		phy.MACPayload = &MACPayload{}
		is_data_packet = true
		is_uplink = true
	case "UnconfirmedDataDown":
		jsonPHY, _ = sjson.Set(jsonPHY, "mhdr.mType", 3)
		phy.MACPayload = &MACPayload{}
		is_data_packet = true
		is_uplink = false
	case "ConfirmedDataUp":
		jsonPHY, _ = sjson.Set(jsonPHY, "mhdr.mType", 4)
		phy.MACPayload = &MACPayload{}
		is_data_packet = true
		is_uplink = true
	case "ConfirmedDataDown":
		jsonPHY, _ = sjson.Set(jsonPHY, "mhdr.mType", 5)
		phy.MACPayload = &MACPayload{}
		is_data_packet = true
		is_uplink = false
	default:
		panic("Error: mType not recognized")
	}

	if is_data_packet {
		if key != "" {
			is_decrypted_data_packet = true
			log.Debug("Received packet AppSKey. Will be used to encrypt its FRMPayload.")
		}

		if frPl := gjson.Get(jsonPHY, "macPayload.frmPayload"); frPl.Exists() {
			phy.MACPayload.(*MACPayload).FRMPayload = []Payload{&DataPayload{}}
		}

		if frameOpts := gjson.Get(jsonPHY, "macPayload.fhdr.fOpts"); frameOpts.Exists() {
			switch cid := gjson.Get(jsonPHY, "macPayload.fhdr.fOpts.0.cid"); cid.String() {
			case "ResetInd", "ResetConf":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 1)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: ResetInd, Payload: &ResetIndPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: ResetConf, Payload: &ResetConfPayload{}}}
				}
			case "LinkCheckReq", "LinkCheckAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 2)
				if is_uplink {
					panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
					//fOpts= []Payload{&MACCommand{CID: LinkCheckReq, Payload: &LinkCheckReqPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: LinkCheckAns, Payload: &LinkCheckAnsPayload{}}}
				}
			case "LinkADRReq", "LinkADRAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 3)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: LinkADRAns, Payload: &LinkADRAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: LinkADRReq, Payload: &LinkADRReqPayload{}}}
				}
			case "DutyCycleReq", "DutyCycleAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 4)
				if is_uplink {
					panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
					//fOpts= []Payload{&MACCommand{CID: DutyCycleAns, Payload: &DutyCycleAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: DutyCycleReq, Payload: &DutyCycleReqPayload{}}}
				}
			case "RXParamSetupReq", "RXParamSetupAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 5)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: RXParamSetupAns, Payload: &RXParamSetupAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: RXParamSetupReq, Payload: &RXParamSetupReqPayload{}}}
				}
			case "DevStatusReq", "DevStatusAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 6)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: DevStatusAns, Payload: &DevStatusAnsPayload{}}}
				} else {
					panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
					//fOpts= []Payload{&MACCommand{CID: DevStatusReq, Payload: &DevStatusReqPayload{}}}
				}
			case "NewChannelReq", "NewChannelAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 7)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: NewChannelAns, Payload: &NewChannelAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: NewChannelReq, Payload: &NewChannelReqPayload{}}}
				}
			case "RXTimingSetupReq", "RXTimingSetupAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 8)
				if is_uplink {
					panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
					//fOpts= []Payload{&MACCommand{CID: RXTimingSetupAns, Payload: &RXTimingSetupAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: RXTimingSetupReq, Payload: &RXTimingSetupReqPayload{}}}
				}
			case "TXParamSetupReq", "TXParamSetupAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 9)
				if is_uplink {
					panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
					//fOpts= []Payload{&MACCommand{CID: TXParamSetupAns, Payload: &TXParamSetupAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: TXParamSetupReq, Payload: &TXParamSetupReqPayload{}}}
				}
			case "DLChannelReq", "DLChannelAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 10)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: DLChannelAns, Payload: &DLChannelAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: DLChannelReq, Payload: &DLChannelReqPayload{}}}
				}
			case "RekeyInd", "RekeyConf":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 11)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: RekeyInd, Payload: &RekeyIndPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: RekeyConf, Payload: &RekeyConfPayload{}}}
				}
			case "ADRParamSetupReq", "ADRParamSetupAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 12)
				if is_uplink {
					panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
					//fOpts= []Payload{&MACCommand{CID: ADRParamSetupAns, Payload: &ADRParamSetupAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: ADRParamSetupReq, Payload: &ADRParamSetupReqPayload{}}}
				}
			case "DeviceTimeReq", "DeviceTimeAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 13)
				panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
			case "ForceRejoinReq":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 14)
				panic("This MACCommand is not implemented by github.com/brocaar/lorawan")
				//fOpts= []Payload{&MACCommand{CID: ForceRejoinReqPayload, Payload: &ForceRejoinReqPayload{}}}
			case "RejoinParamSetupReq", "RejoinParamSetupAns":
				jsonPHY, _ = sjson.Set(jsonPHY, "macPayload.fhdr.fOpts.0.cid", 15)
				if is_uplink {
					fOpts = []Payload{&MACCommand{CID: RejoinParamSetupAns, Payload: &RejoinParamSetupAnsPayload{}}}
				} else {
					fOpts = []Payload{&MACCommand{CID: RejoinParamSetupReq, Payload: &RejoinParamSetupReqPayload{}}}
				}
			}
			phy.MACPayload.(*MACPayload).FHDR.FOpts = fOpts
		}
	}

	//fmt.Printf("Modified JSON is %s\n", jsonPHY)

	if err := json.Unmarshal([]byte(jsonPHY), phyAlias(&phy)); err != nil {
		fmt.Println("Error unmarshaling json: ", err)
	}

	if is_decrypted_join_accept {
		var key_obj AES128Key

		if err := key_obj.UnmarshalText([]byte(key)); err != nil {
			log.Error("Unmarshall error with key: ", key)
			panic(err)
		}

		// The EUI and devnonce fields aren't used but required
		if err := phy.SetDownlinkJoinMIC(JoinRequestType, EUI64{}, DevNonce(0), key_obj); err != nil {
			log.Error("An error ocurred when trying to set the MIC to JoinAccept")
			panic(err)
		}
		if err := phy.EncryptJoinAcceptPayload(key_obj); err != nil {
			log.Error("An error ocurred when encrypting the JoinAccept")
			panic(err)
		}

	} else if is_decrypted_data_packet {
		var key_obj AES128Key

		if err := key_obj.UnmarshalText([]byte(key)); err != nil {
			log.Error("Unmarshall error with key: ", key)
			panic(err)
		}

		if err := phy.EncryptFRMPayload(key_obj); err != nil {
			log.Error("Error encrypting FRMPayload")
			panic(err)
		}

	}

	// Debug lines
	//fmt.Printf("Unmarshaled PHY is %v\n", phy)
	// phyJSON, err := phy.MarshalJSON()
	// if err != nil {
	// 	fmt.Println("Error marshaling PHY")
	// 	panic(err)
	// }
	//fmt.Printf("Marshaled PHY: %s\n", string(phyJSON))

	str, err := phy.MarshalText()
	if err != nil {
		panic(err)
	}
	result := string(str)

	// If nwkSKey provided, sign data packet.
	if is_data_packet && nwkskey != "" {
		log.Debug("Received packet NwkSKey. Signing data packet")
		result = signPacket(result, nwkskey, "")

		// If it's a JoinRequest and key provided, sign it
	} else if mType == "JoinRequest" && key != "" {
		result = signPacket(result, key, "")
	}

	return result

}
