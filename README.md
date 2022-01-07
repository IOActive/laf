# LoRaWAN Auditing Framework - ALPHA VERSION

IoT deployments just keep growing and one part of that significant grow is composed of millions of LPWAN  (low-power wide-area network) sensors deployed at hundreds of cities (Smart Cities) around the world, also at industries and homes. One of the most used LPWAN technologies is LoRa for which LoRaWAN is the network standard (MAC layer). LoRaWAN is a secure protocol with built in encryption but implementation issues and weaknesses affect the security of most current deployments.

This project intends to provide a series of tools to craft, parse, send, analyze and crack a set of LoRaWAN packets in order to audit or pentest the security of a LoraWAN infrastructure.

Below, the structure of this repository:

    |-- tools 
        |-- UdpSender.py
        |-- UdpProxy.py
        |-- TcpProxy.py
        |-- lorawan
            |-- BruteForcer.py
            |-- MicGenerator.py
            |-- PacketCrafter.py
            |-- PacketParser.py
            |-- SessionKeysGenerator.py 
            |-- Loracrack (https://github.com/matiassequeira/Loracrack/tree/master) 
        |-- utils
            |-- DevAddrChanger.py
            |-- Fuzzer.py    
            |-- FileLogger.py
    |-- auditing
        |-- datacollectors
            |-- MqttCollector.py
            |-- UdpForwarderProxy.py
        |-- analyzers
            |-- LafProcessData.py
            |-- bruteForcer
                |-- LafBruteforcer.py
                |-- keys
            |-- dataanalysis
                |-- LafPacketAnalysis.py
            |-- printer
                |-- LafPrinter.py
        |-- db
            |-- __init__.py
            |-- Models.py
            |-- Service.py
    |-- lorawanwrapper 
            |-- LorawanWrapper.py
            |-- utils 
                |-- jsonUnmarshaler.go
                |-- lorawanWrapper.go
                |-- micGenerator.go
                |-- sessionKeysGenerator.go
    |-- scripts
        |-- gateway_channel_changer
            |-- LoRa-GW-Installer.sh
            |-- Continuous-Channel-Switch.sh
            |-- LoRa-GW-Channel-Setup.sh

## Getting Started

We provide different options to have your LoraWAN Auditing Framework up and running:

1. The first is for those people that want to install it locally. We recommend this option if your main goal is to use pentesting tools located in `tools/` dir, in order to avoid problems with docker port mapping.
2. The other option is for those people that want to run it into a Docker container, thus avoiding to manually install any dependency. We recommend this option in case you want use the analyzers and don't have much time to manually set up the environment.
3. Of course, you can run LAF locally and use Postgres DB from the Docker container instead of sqlite ;). LAF will try to connect to Postgres through `localhost`. See instructions below to set up Docker.

### Install LAF in your local environment

These instructions will get you a copy of the project and its dependencies in your local machine. Commands below are for a Debian based environment:

1. Clone this repository: `git clone --recurse-submodules https://github.com/IOActive/laf.git`
2. Install python3:
	1. `sudo apt-get update`
	2. `sudo apt-get install python3.6`
3. Download and install python dependencies:
	1. `sudo pip3 install paho-mqtt && sudo pip3 install sqlalchemy && sudo pip3 install psycopg2-binary &&sudo pip3 install python-dateutil`
4. Set PYTHONPATH and ENVIRONMENT
	1. `cd laf && export PYTHONPATH=$(pwd) && export ENVIRONMENT='DEV'`
5. Install and setup golang: 
    1. Download golang from https://golang.org/dl/ depending on your operating system.
    2. Move to the folder where the go installer was downloaded: `cd ~/Downloads`
    3. Decompress the installer: `sudo tar -C /usr/local -xvzf YOUR_GOLANG_FILE`
    4. Export to PATH: `export PATH=$PATH:/usr/local/go/bin`
    5. Set GOPATH: `export GOPATH="$HOME/go"`
6. Compile go library:
    1. `cd laf/lorawanwrapper/utils`
    2. `go build -o lorawanWrapper.so -buildmode=c-shared jsonUnmarshaler.go lorawanWrapper.go micGenerator.go sessionKeysGenerator.go hashGenerator.go`
7. Depending on which DB you'd like to use:

    a. PostreSQL: Follow instructions 'Install LAF using Docker' until 3rd step.

    b. SQLite:

    1. `cd laf/auditing/db`
    2. Modify `__init__.py` with your preferred text editor and comment the lines to be used with Postgres (DB connection and environment variables) an uncomment the line to be used with sqlite.

And that's it! 

### Install LAF using Docker

This approach avoids dealing with the installation of dependencies and start a PostgreSQL DB where the tools save packets and data.
Containers:

* Tools.
* PostgreSQL.
* PgAdmin4.

Steps:
1. Clone this repository: 
        `git clone https://github.com/IOActive/laf.git`
2. Go to `cd laf/`
2. Start containers:
	`docker-compose up --build`
3. If you want to use the tools into the container
	`docker exec -ti laf_tools_1 /bin/bash`
4. Enjoy!

#### pgAdmin database connection

You can check data in DB using pgAdmin:

First, access to pgAdmin:

* URL: http://localhost:5001
* User: pgadmin
* Pass: pgadmin

Then, you need to add the server:

* Host: db
* Port: 5432
* User: postgres
* Pass: postgres

## Tools description

Here is description of the directories and the tools / function inside them.

### /tools

The main purpose of the tools provided in this directory is to ease the execution of a penetration test to a LoRaWAN infrastructure.

#### UdpSender.py

This tool is intended to send uplink packets (to the network server or gatewayBridge, depending on the infrastructure) or downlink packets (to the packet-forwarder). Optionally, packets can be fuzzed and a valid MIC can be calculated.

Optional arguments:

    -h, --help            show this help message and exit
    --lcl-port LCL_PORT   Source port, eg. --lcl-port=623.
    --timeout TIMEOUT     Time in seconds between every packet sent. Default is
                            1s. In this time, the sender will listen for replies.
    --repeat              Send message/s multiple times
    --fuzz-out FUZZ_OUT [FUZZ_OUT ...]
                            Fuzz data sent to dest port (see fuzzing modes in
                            utils/fuzzer.py), eg. --fuzz-out 1 2.
    --key KEY             Enter the key (in hex format, a total of 32 characters
                            / 16 bytes) to sign packets (calculate and add a new
                            MIC). Note that for JoinRequests it must be the
                            AppKey, and the NwkSKey for Data packets. This cannot
                            be validated beforehand by this program. eg.
                            00112233445566778899AABBCCDDEEFF
    -a DEVADDR, --devaddr DEVADDR
                            DeviceAddress to impersonate, given in hex format (8
                            characters total), eg. AABB0011.
    --fcnt FCNT           The frame counter to be set in the given data packet.
                            This wouldn't work in a JoinRequest/JoinAccept since
                            this packets don't have a fCnt

Required arguments:

    --dst-ip DST_IP       Destination ip, eg. --dst-ip 192.168.3.101.
    --dst-port DST_PORT   Destination port, eg. --dst-port 623.
    --data DATA           UDP packet. It can also be added more packets in
                            "data" array at the end of this script. The packet
                            must be a byte string (you will have to escape double
                            quotes). ***EXAMPLE*** with the packet_forwarder
                            format: --data "b'\x02\xe67\x00\xb8\'\xeb\xff\xfez\x80
                            \xdb{\"rxpk\":[{\"tmst\":2749728315,\"chan\":0,\"rfch\
                            ":0,\"freq\":902.300000,\"stat\":1,\"modu\":\"LORA\",\
                            "datr\":\"SF7BW125\",\"codr\":\"4/5\",\"lsnr\":9.5,\"r
                            ssi\":-76,\"size\":23,\"data\":\"AMQAAAAAhQAAAgAAAAAAA
                            ACH9PRMJi4=\"}]}'" ***EXAMPLE*** using the gatevice
                            [GV] format sending in inmediate mode, in BW125 and
                            freq 902.3 is "b'{\"tx_mode\": 0, \"freq\": 902.3,
                            \"rfch\": 0, \"modu\": 16, \"datarate\": 16,
                            \"bandwidth\":3, \"codr\": 1, \"ipol\":false,
                            \"size\": 24, \"data\":
                            \"QOOL8AGA6AMCnudJqz3syCkeooCvqbSn\", \"class\": 2}'"

Example:

To send a single packet every 2 seconds to (localhost, 10001) from port 10000 fuzzing randomly the MIC and the FCounter:

    python3 UdpSender.py --lcl-port 10000 --dst-ip 127.0.0.1 --dst-port 10001 --timeout 2 --fuzz-out 4 5 --data "b'\x02\xe67\x00\xb8\'\xeb\xff\xfez\x80\xdb{\"rxpk\":[{\"tmst\":2749728315,\"chan\":0,\"rfch\":0,\"freq\":902.300000,\"stat\":1\"modu\":\"LORA\",\"datr\":\"SF7BW125\",\"codr\":\"4/5\",\"lsnr\":9.5,\"rssi\":-76,\"size\":23,\"data\":\"AMQAAAAAhQAAAgAAAAAAAACH9PRMJi4=\"}]}'"

#### UdpProxy.py

This UDP proxy is mainly intended to be placed between a series gateways (packet_forwarders) and a network server or gateway bridge depending on the infraestructure being evaluated. It also offers the posibility to fuzz data in the desired direction (uplink or downlink)

Optional arguments:

    -h, --help            show this help message and exit
    --collector-port COLLECTOR_PORT
                            Packet forwarder data collector port, eg. --collector-
                            port 1701. See
                            auditing/datacollectors/PacketForwarderCollector.py
    --collector-ip COLLECTOR_IP
                            Packet forwarder data collector ip. Default is
                            localhost. eg. --collector-ip 192.168.1.1. See
                            auditing/datacollectors/PacketForwarderCollector.py
    --fuzz-in FUZZ_IN [FUZZ_IN ...]
                            Fuzz data sent to dst-port in the given modes (see
                            fuzzing modes in utils/fuzzer.py), eg. --fuzz-in 1 2
                            ...
    --fuzz-out FUZZ_OUT [FUZZ_OUT ...]
                            Fuzz data sent to (source) port in the given modes
                            (see fuzzing modes in utils/fuzzer.py), eg. --fuzz-out
                            1 2 ...
    -k KEY, --key KEY     Enter a device AppSKey (in hex format, a total of 32
                            characters / 16 bytes) to decrypt its FRMPayload and
                            print it in plain text. You can also enter the AppKey
                            if you wish to decrypt a given Join Accept. eg.
                            00112233445566778899AABBCCDDEEFF
    -p PATH, --path PATH  Filepath where to save the data. If not given, data
                            will not be saved.
    --no-log              Do not print UDP packages into console
    --no-parse            Do not parse PHYPayload. If this option is selected,
                            Golang librarys from /lorawanwrapper/ won't be
                            imported (golang libs compiling is not required)
                        
Required arguments:

    --port PORT           The local port to listen, eg. --port 623.
    --dst-ip DST_IP       Destination host ip, eg. --dst-ip 192.168.3.101.
    --dst-port DST_PORT   Destination host port, eg. --dst-port 623.

Example:

To send packets received in the port 1234 to (localhost, 1235) and vicecersa. Packets received in the port will be fuzzed (the devNonce will be changed randonly) and forwarded to (localhost, 1235).

    python3 UdpProxy.py --port 1234 --dst-ip 127.0.0.1 --dst-port 1235 --fuzz-in 9

#### TcpProxy.py

This TCP proxy is mainly intended to be placed between the network server and a MQTT brokers. It also offers the posibility to fuzz data.

Optional arguments:

    -h, --help            show this help message and exit
    --fuzz-in FUZZ_IN [FUZZ_IN ...]
                        Fuzz data sent to dst-port in the given modes (see
                        fuzzing modes in utils/fuzzer.py)

Required arguments:

    --lcl-port LCL_PORT   The local port to listen, eg. --lcl-port=623.
    --dst-ip DST_IP       Destination host ip, eg. --dst-ip=192.168.3.101.
    --dst-port DST_PORT   Destination host port, eg. --dst-port=623.

Example:

Send and receive data from (localhost, 1884) and (localhost, 1883)

        python3 TcpProxy.py --lcl-port 1884 --dst-ip 127.0.0.1 --dst-port 1883
 
 #### tools/lorawan
 
 This directory contains a series of scripts to parse, craft, bruteforcer, etc. LoRaWAN a packets. 
 
 ##### lorawan/BruteForcer.py

This script receives a JoinAccept or JoinRequest in Base64 and tries to decrypt its AppKey with a set of possible keys which can be provided in a file or can be generated on the fly.

Optional arguments:

    -h, --help            show this help message and exit
    -k KEYS, --keys KEYS  File containing a list of keys, separated by \n. Will
                            use /auditing/analyzers/bruteForcer/keys.txt by
                            default
    --dont-generate       Select this options if you don't want to generate keys
                            on the fly with the following combinations: 1- Combine
                            the first byte and the last fifteeen bytes. eg.
                            AABBBBBBBBBBBBBBBBBBBBBBBBBBBBBB 2- Combine even and
                            odd bytes position equally. eg.
                            AABBAABBAABBAABBAABBAABBAABBAABB 3- The first 14 bytes
                            in 00 and combine the last 2. eg.
                            0000000000000000000000000000BA01

Required arguments:

    -a ACCEPT, --accept ACCEPT
                    Join Accept in Base64 format to be bruteforced. eg. -a
                    IHvAP4MXo5Qo6tdV+Yfk08o=
    -r REQUEST, --request REQUEST
                    Join Request in Base64 format to be bruteforced. eg.
                    -r AMQAAAAAhQAAAgAAAAAAAADcYldcgbc=

Example:

Crack a JoinRequest with a set of keys from my-keys.txt and also generate aprox. 200000 more dinamically.

    python3 BruteForcer.py -a IHvAP4MXo5Qo6tdV+Yfk08o= -r AMQAAAAAhQAAAgAAAAAAAADcYldcgbc= -k ./my-keys.txt

##### lorawan/MicGenerator.py

This scripts receives a PHYPayload packet in Base64 and a key which can be the NwkSKey of the AppKey depending on the packet type and generates the new MIC.

Optional arguments:

    -h, --help            show this help message and exit
    --jakey JAKEY         [JoinAccept ONLY]. Enter the key used to encrypt the
                            JoinAccept previously (in hex format, a total of 32
                            characters / 16 bytes). This cannot be validated
                            beforehand by this program. eg.
                            00112233445566778899AABBCCDDEEFF. A valid key sample
                            for the JoinAccept "IB1scNmwJRA32RfMbvwe3oI=" is
                            "f5a3b185dfe452c8edca3499abcd0341"

Required arguments:

    -d DATA, --data DATA  Base64 data to be signed. eg. -d
                            AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=
    -k KEY, --key KEY     Enter the new key (in hex format, a total of 32
                            characters / 16 bytes) to sign packets (calculate and
                            add a new MIC). Note that for JoinRequest/JoinAccept
                            it must be the AppKey, and the NwkSKey for Data
                            packets. This cannot be validated beforehand by this
                            program. eg. 00112233445566778899AABBCCDDEEFF

Example:

Sign the given PHYPayload with the AppKey 00112233445566778899AABBCCDDEEFF.

    python3 MicGenerator.py -d AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU= -k 00112233445566778899AABBCCDDEEFF

##### lorawan/PacketCrafter.py

This script receives a lorawan JSON packet and tranforms it to Base64. It does the inverse as packetParser.py, so the output of that script can be used here and vice-versa.

Optional arguments:

    -h, --help            show this help message and exit
    -k KEY, --key KEY     Enter a device AppSKey or AppKey (in hex format, a
                            total of 32 characters / 16 bytes) to encrypt the
                            FRMPayload or a Join Accept. eg.
                            F5A3B185DFE452C8EDCA3499ABCD0341
    --nwkskey NWKSKEY     Enter the network session key if you'd like to
                        generate a data packet with a valid MIC.

Required arguments:

    -j JSON, --json JSON  JSON object to parse. eg. -j '{"mhdr":
                            {"mType":"JoinRequest","major":"LoRaWANR1"},"macPayloa
                            d":{"joinEUI":"55d239ac716f234d","devEUI":"b827eb891cf
                            50003","devNonce":51639},"mic":"7005c4a5"}'

Example:

Obtain a JoinRequest PHYPayload in Base64 with given in the JSON with the values passed into it.

    python3 PacketCrafter.py -j '{"mhdr":{"mType":"JoinRequest","major":"LoRaWANR1"},"macPayload":{"joinEUI":"55d239ac716f234d","devEUI":"b827eb891cf50003","devNonce":51639},"mic":"7005c4a5"}'
                          
##### lorawan/PacketParser.py 

This script parses and prints a single LoRaWAN PHYPayload data in Base64. It does the inverse as packetCrafter.py, so the output of that script can be used here and vice-versa.

Optional arguments:

    -h, --help            show this help message and exit
    -k KEY, --key KEY     Enter a device AppKey or AppSKey depending on the
                            packet to be decrypted (join accept or data packet).
                            Must be in hex format, a total of 32 characters / 16
                            bytes. eg. 00112233445566778899AABBCCDDEEFF

Required arguments:

    -d DATA, --data DATA  Base64 data to be parsed. eg. -d
                        AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=

Example:

Obtain the JoinRequest in JSON format from the example above.

    python3 PacketParser.py -d AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=

##### lorawan/SessionKeysGenerator.py 

This script receives a JoinAccept and a JoinRequest in Base64, and an AppKey to generate the session keys. An example of the usage:

Optional arguments:

    -h, --help            show this help message and exit

Required arguments:

    -a JACCEPT, --jaccept JACCEPT
                        JoinAccept payload in base64
    -r JREQUEST, --jrequest JREQUEST
                        JoinRequest payload in base64
    -k KEY, --key KEY     Enter a device AppKey (in hex format, a total of 32
                        characters / 16 bytes). eg.
                        00112233445566778899AABBCCDDEEFF

Example:

Obtain the AppSKey and NwkSKey with the following join data.

    python3 SessionKeysGenerator.py -r AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU= -a IB1scNmwJRA32RfMbvwe3oI= -k f5a3b185dfe452c8edca3499abcd0341

##### lorawan/utils/*

These are auxiliary functions used by the `UdpSender.py` and `UdpProxy.py`. In `Fuzzer.py` you can see  fuzzing modes implemented.

### /auditing

The general purpose of this directory is to collect LoRaWAN packets and analyze different aspects of the traffic, as well as trying a set of keys to try to bruteforce the AppKey.

#### /auditing/datacollectors

This directory contains a set of scripts that receive LoRaWAN packets from different sources (i.e. gateway packet_forwarder, The Things Network, etc.) and save them into files, with a standard format. This files should be fetched later by the script `/auditing/analyzers/LafProcessData.py` to execute different sub-tools.

##### datacollectors/GenericMqttCollector.py

This script connects to the mqqt broker, retrieves all the topics and saves messages into a file in the specified field. The filename is composed by the date that this script was started.

Optional arguments:

    -h, --help            show this help message and exit
    --collector-id COLLECTOR_ID
                            The ID of the dataCollector. This ID will be
                            associated to the packets saved into DB. eg. --id 1
    --organization-id ORGANIZATION_ID
                            The ID of the dataCollector. This ID will be
                            associated to the packets saved into DB. eg. --id 1
    --topics TOPICS [TOPICS ...]
                            List the topic(s) you want to suscribe separated by
                            spaces. If nothing given, default will be "#.

Required arguments:

    --ip IP               MQTT broker ip, eg. --ip 192.168.3.101.
    --port PORT           MQTT broker port, eg. --port 623.

Example:

Connect to MQTT the broker with ip 200.200.200.200 in the default port (1883).

    python3 GenericMqttCollector.py --ip 200.200.200.200 --port 1883

##### datacollectors/LoraServerIOCollector.py

This script connects to a loraserver.io mqqt broker and saves messages into
the DB. You must specify a unique collectorID and you can specify the topics
you want to suscribe to.

Optional arguments:

    -h, --help            show this help message and exit
    --port PORT           MQTT broker port, eg. --port 623. Default 1883.
    --collector-id COLLECTOR_ID
                            The ID of the dataCollector. This ID will be
                            associated to the packets saved into DB. eg. --id 1
    --organization-id ORGANIZATION_ID
                            The ID of the dataCollector. This ID will be
                            associated to the packets saved into DB. eg. --id 1
    --topics TOPICS [TOPICS ...]
                            List the topic(s) you want to suscribe separated by
                            spaces. If nothing given, default will be "#.

Required arguments:

    --ip IP               MQTT broker ip, eg. --ip 192.168.3.101.

##### datacollectors/PacketForwarderCollector.py

This script receives UDP packets from the UDP proxy in the gateway
packet_forwarder format and persists them.

Optional arguments:

    -h, --help            show this help message and exit
    --collector-id COLLECTOR_ID
                            The ID of the dataCollector. This ID will be
                            associated to the packets saved into DB. eg. --id 1
    --organization-id ORGANIZATION_ID
                            The ID of the dataCollector. This ID will be
                        associated to the packets saved into DB. eg. --id 1

Required arguments:

    -n NAME, --name NAME  Unique string identifier of the Data Collector. eg.
                        --name semtech_collector
    -p PORT, --port PORT  Port where to listen for UDP packets. --port 1702.

Example:

Record data between a gateway sending to the local port 1700 and a network xserver listening in (localhost, 1701). Save the data in `./` directory.

        python3 PacketForwarderCollector.py --name semtech_collector --port 1700


#### analyzers/LafProcessData.py


This script reads a from a file or files or stdin and executes different sub-tools. Depending on the option selected you can execute an analysis of the LoRaWAN traffic, try to bruteforce the AppKey, or parse all the packets received. These options can be combined.

Optional arguments:

	This script reads retrieves packets from DB and executes different sub-tools.
	Then, each sub-tool will save output data into the DB. See each option for
	more information.

	optional arguments:
	  -h, --help            show this help message and exit
	  -a, --analyze         Collect and analyze different aspects from traffic. If
				Bruteforcer (-b) is activated, results will be
				corelated
	  -b, --bforce          Try to bruteforce the AppKeys with JoinRequests and
				JoinAccepts payloads
	  -k KEYS, --keys KEYS  [Bruteforcer] Filepath to keys file. If not provided,
				"bruteForcer/keys.txt" will be used
	  --no-gen              [Bruteforcer] Don't generate keys, only try keys from
				files
	  -p, --parse           Parse the PHYPayload into readable information
	  --from-id FROM_ID     Packet ID from where to start processing.
	  --to-id TO_ID         Last packet ID to be processed.

Example:

Process packets in the DB starting from packet ID 1000, execute a traffic analysis, and try to crack AppKeys given in my-keys.txt, but don't generate dinamically more keys.

        python3 LafProcessData.py -a -b -k my-keys.txt --no-gen --from-id 1000

#### analyzers/bruteforcer, analyzers/dataanalysis, analyzers/parser and analyzers/utils

These scripts provide the functionality orchested by LafProcessData.py. Below, the alerts that are implemented by `LafPacketAnalysis.py` and `LafBruteForcer.py`:

| ID      | Title                                                    | Analyzer             | Risk level | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Recommended Action                                                                                                                                                                                                                                                                                                                               |
|---------|----------------------------------------------------------|----------------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| LAF-001 | DevNonce repeated                                        | LafPacketAnalysis.py | Low        | DevNonces for each device should be random enough to not collide. If the same DevNonce was repeated in many messages, it can be inferred that a device is under a replay attack. This is, an attacker who captured a JoinRequest and is trying to send it again to the gateway.                                                                                                                                                                                                                                                                                                                                                                                                                      | Check how DevNonces are generated: the function that generates them should be implemented using a random library. Moreover, you have to make sure that the server checks for historic DevNonces (they should be persisted in DB), in order not to accept an old valid JoinRequest previously sent by the device and thus generate a new session. |
| LAF-002 | DevEUIs sharing the same DevAddr                         | LafPacketAnalysis.py | Info       | Two different devices might have been assigned the same DevAddr. This isn't a security threat.                                                                                                                                                                                                                                                                                                                                                                                                                                                | If the device is over the air activated (OTAA): Check logic used to assign DevAddrs, and make sure that the server doesn't assign the same DevAddr to different devices. If the device is activated by personalization (ABP): Check the DevAddr configured in a device's firmware is unique in the lorawan network.                              |
| LAF-003 | Join replay                                              | TODO                 | Medium     | A duplicated join request packet was detected, which may imply that the lorawan server is under a replay attack. This is, an attacker that may have captured a previous join request packet and is sending it again to the lorawan server, in order to try to generate a new session.                                                                                                                                                                                                                                                                                                                                                                                                                | Check how DevNonces are generated: the function that generates them should be implemented using a random library. Moreover, you have to make sure that the server checks for historic DevNonces (they should be persisted in DB), in order not to accept an old valid JoinRequest previously sent by the device and thus generate a new session. |
| LAF-004 | Uplink data packets replay                               | TODO                 | Medium     | A duplicated uplink packet was detected, which may imply that the lorawan server is under a replay attack. This is, an attacker that may have captured an uplink packet (sent from the device) and is sending it again to the lorawan server.                                                                                                                                                                                                                                                                                                                                                                                                                                                        | In over the air activated (OTAA) devices: Make sure that session keys are re-generated after every device reset or counter overflow to avoid any effect from this attack. With activated by personalization (ABP) devices from lorawan v1.0.*, nothing can be done to prevent a replay attack except from switching the device to OTAA.          |
| LAF-005 | Downlink data packets replay                             | TODO                 | High       | A duplicated downlink packet was detected.  The server is responding to a replay attack or is generating an atypical traffic to devices                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Check servers' logs and check that previous recommended action are implemented                                                                                                                                                                                                                                                                   |
| LAF-006 | Possible ABP device (counter reset and no join)          | LafPacketAnalysis.py | High       | If the counter was reset (came back to 0), the DevAddr is kept the same, and no previous Join process was detected, may imply that the device is activated by personalization (ABP). ABP devices implementation is discouraged because no join process is done, which means that session keys are kept the same forever. A device that doesn't change its session keys is prone to different attacks such as eaveasdrop or replay.                                                                                                                                                                                                                                                                   | All activated by personalization (ABP) devices should be replaced for over the air activated (OTAA) devices if possible. The implementation of ABP devices is discouraged.                                                                                                                                                                       |
| LAF-007 | Received smaller counter than expected (distinct from 0) | LafPacketAnalysis.py | Medium     | If an attacker obtains a pair of session keys (for having stolen the AppKey in OTAA devices or the AppSKey/NwkSKey in ABP devices), he/she would be able to send fake valid data to the server. For the server to accept spoofed messages, it is required for the FCnt (Frame Counter) of the message to be higher than the FCnt of the last message sent. In an scenario where the original spoofed device keeps sending messages, the server would start to discard (valid) messages since they would have a smaller FCnt. Hence, when messages with a smaller FCnt value than expected by the lorawan server are being received, it is possible to infer that a parallel session was established. | If the device is over the air activated device (OTAA), change its AppKey because it was probably compromised. If it's activated by personalization, change its AppSKey and NwkSKey. Moreover, make sure that the lorawan server is updated and is not accepting duplicated messages.                                                             |
| LAF-008 | Password cracked with JoinRequest                        | LafBruteforcer.py    | High       | It was possible to decrypt a JoinRequest message using a known AppKey.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Use different AppKeys than the ones provided by vendors or use more random keys.                                                                                                                                                                                                                                                                 |
| LAF-009 | Password cracked                                         | LafBruteforcer.py    | High       | The AppKey of the device was found trying with a well-known or nonrandom string. It was decrypted using a pair of join messages (Request and Accept).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Use a random key generator for the AppKey instead of using ones provided by vendors. Moreover, don't set the same AppKey to more than one device and don't generate AppKeys using a predictable logic (eg. incremental values, flip certain bytes, etc.)                                                                                         |
| LAF-010 | Gateway changed location                                 | LafPacketAnalysis.py | Medium     | If the gateway is not supposed to change its location. It may have been stolen, moved, or a fake gateway may be trying to impersonate the legitimate Gateway.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Make sure the gateway wasn't tampered, both physically or logically.                                                                                                                                                                                                                                                                             |
### /lorawanwrapper

This directory provides a set of wrappers for the library <https://github.com/brocaar/lorawan/>, which is written in Golang. These functions are implemented by  the tools.

### /scripts

Here you will find a series of scripts intended to automate different tasks. Make sure to give them execution permission if necessary (`chmod +x your_script` for Linux/MacOS).

#### /scripts/lorawan_gateway_scripts

Easily set up your gateway and switch its channels for sniffing purposes. For more information about how to use them, you can see the readme in this directory.

##### gateway_channel_changer/LoRa-GW-Installer.sh

This script is used to install all necessary software packages on a Raspberry PI for building up a LoRaWAN Gateway in conjunction with a connected LoRa Concentrator (iC980-SPI, RHF0M301-SPI, RAK831-SPI or any other by manual setup). 

##### gateway_channel_changer/Continuous-Channel-Switch.sh and gateway_channel_changer/LoRa-GW-Channel-Setup.sh

Since it is not possible to know in which frequencies LoRa devices are operating, we have created a script that can switch gateways channels from the  **US915 and EU868 frequency bands** for sniffing purposes. Although there are professional and expensive gateways that support 32 or 64 channels, most gateways support up to 8 channels. This script is intended to run in this kind of gateways.

At least in the US915 frequency band, the first 8 channels are the most used. But there are well known implementations that use another group of channel, as for example The Things Networks, which use the second group (8-15) of channels for uplink communication.

Currently we don't support other frequency bands but, with few changes to these scripts you'd be able to do this on your own :).

## Demo video

We uploaded a video of this framework in action (same scenario presented at [BlackHat 2019](https://www.blackhat.com/us-19/arsenal/schedule/index.html#lorawan-auditing-framework-16986)): <https://youtu.be/Mm6A2RVNoCs>. Detailed steps of the demo are in the Youtube video  description.

## Authors

* **Matias Sequeira** - [matiassequeira](https://github.com/matiassequeira)
* **Esteban Martínez Fayó** - [emfayo](https://github.com/emfayo)

### Contributors

* **Sebastian Scheibe** - *Contributed with scripts/lorawan_gateway_scripts* - [sebascheibe](https://github.com/sebascheibe)

## Contributing

TODO

## Acknowledgments

* MQTT client for Python: <https://github.com/iwanbk/nyamuk/>
* LoRaWAN library in Golang: <https://github.com/brocaar/lorawan/>
* Functions to handle JSON in Golang <https://github.com/tidwall/sjson> and <https://github.com/tidwall/gjson>
* The base of our tcpProxy: <https://gist.github.com/voorloopnul/415cb75a3e4f766dc590>
* Loracrack: forked and modified original repository <https://github.com/applied-risk/Loracrack>

## License

This project is licensed under BSD-3-Clause License.
