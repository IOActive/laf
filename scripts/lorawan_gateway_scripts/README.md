# LoRaWAN Gateway Scripts

## LoRa-GW-Installer.sh ##

This script is used to install all necessary software packages on a Raspberry PI for building up a LoRaWAN Gateway in conjunction with a connected LoRa Concentrator (iC980-SPI, RHF0M301-SPI, RAK831-SPI or any other by manual setup). If there was any wrong input you can re run the script to update any settings. 

Run the script in command line:
```
      sudo bash  LoRa-GW-Installer.sh
```

The script creates a source folder “lora” inside the directory where the installer script is executed. Inside of that “lora” folder the official github projects “packet_forwarder” and “lora_gateway” are cloned and build before a configuration menu appears. Below an example setup:
 ```
------ Configuration ------
 
Choose LoRa Concentrator from list:

<1> iC980A-SPI
<2> RHF0M301-SPI
<3> RAK831-SPI
<4> Another one. Manual setup required.

Please enter number: 2
 ```
-> The script now creates a start script (./lora/start_lora_gateway.sh) that is used to reset the LoRa concentrator at startup before running the packet-forwarder. Here depending on the used LoRa Concentrator a different reset pin has to be defined. It’s the pin at the RPI where the reset pin of the LoRa Concentrator is connected to.
Manual setup (option 4) would lead to the following configuration options:
 ```
------ Manual setup ------

Name of LoRa concentrator:
My-LoRa-Concentrator

GPIO pin of Raspberry PI where concentrator reset pin is connected to:
16

------ Setting up for My-LoRa-Concentrator concentrator ------
 ```
The configuration then asks for the region of the Gateway. Currently only EU868 and US915 regions are supported: 
 ```
------ Setting up for RHF0M301-SPI concentrator ------
 
Choose frequency band / region of Gateway:
<1> US915
<2> EU868
Please enter number: 1

------ Setting up US915 region ------
```

After choosing the frequency band the corresponding global conf with the frequency patterns is copied from ./lora/packet_forwarder/lora_pkt_fwd/cfg/ to ./lora/packet_forwarder/lora_pkt_fwd/global_conf.json

Then enter the connection details to connect the Gateway to the LoRaWAN Network server:
```
IP/URL of LoRaWAN-Server:
my-lorawan-server.com
LoRaWAN-Server UP Port:
1680
LoRaWAN-Server DOWN Port:
1680
 
Creating lorawan-gateway.service file in /etc/systemd/system/
Created symlink /etc/systemd/system/multi-user.target.wants/lorawan-gateway.service → /etc/systemd/system/lorawan-gateway.service.

=========================================================================
 
 SETUP DONE! CONGRATULATIONS! :)
 To start the LoRa Gateway please run the following command in a terminal:
 
  > gw_start
 
 or use the created service to run it in the background:
 
  > sudo service lorawan-gateway start
  > sudo service lorawan-gateway stop
  > sudo service lorawan-gateway status
 
 Configuration files are located in:
  /usr/bin/start_lora_gateway.sh [SERVICE]
  /home/pi/lora/start_lora_gateway.sh [TERMINAL APP]
  /etc/systemd/system/lorawan-gateway.service
  /home/pi/lora/packet_forwarder/lora_pkt_fwd/global_conf.json
  /home/pi/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
 
=========================================================================
```

## LoRa-GW-Channel-Setup.sh ##

This script is used to change that the channel configuration the LoRa Gateway is using for listening to LoRaWAN devices. 

### Prerequisites

Make sure to follow these steps:

1. Place this script inside the /lora/packet_forwarder/lora_pkt_fwd/ folder where global_conf.json file is located. 
2. Configure a **service** for the packet forwarder with the **restart** option. If you used the `LoRa-GW-Installer.sh` script, this is already done.

Run it specifying the [CHANNEL_CONF] as well as the [BAND_REGION] parameter.

### Usage 

```
            sudo bash LoRa-GW-Channel-Setup.sh [CHANNEL_CONF] [BAND_REGION]
```            

Below you can find a table to identify the correct [CHANNEL_CONF] parameter used to setup a specific channel group
(__setup_freq_0__ and __setup_freq_1__ are the frequency parameters that are written in the global_conf.json file to setup the corresponding channel group.):

US915 BAND:

| CHANNEL_CONF | setup_freq_0 | setup_freq_1  | Channel_1 | Channel_2 | Channel_3 | Channel_4 | Channel_5 | Channel_6 | Channel_7 | Channel_8 |
| ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
| 0 | 902700000 | 903400000 | 902300000 | 902500000 | 902700000 | 902900000 | 903100000 | 903300000 | 903500000 | 903700000 |
| 1 | 904300000 | 905000000 | 903900000 | 904100000 | 904300000 | 904500000 | 904700000 | 904900000 | 905100000 | 905300000 |
| 2 | 905900000 | 906600000 | 905500000 | 905700000 | 905900000 | 906100000 | 906300000 | 906500000 | 906700000 | 906900000 |
| 3 | 907500000 | 908200000 | 907100000 | 907300000 | 907500000 | 907700000 | 907900000 | 908100000 | 908300000 | 908500000 |
| 4 | 909100000 | 909800000 | 908700000 | 908900000 | 909100000 | 909300000 | 909500000 | 909700000 | 909900000 | 910100000 |
| 5 | 910700000 | 911400000 | 910300000 | 910500000 | 910700000 | 910900000 | 911100000 | 911300000 | 911500000 | 911700000 |
| 6 | 912300000 | 913000000 | 911900000 | 912100000 | 912300000 | 912500000 | 912700000 | 912900000 | 913100000 | 913300000 |
| 7 | 913900000 | 914600000 | 913500000 | 913700000 | 913900000 | 914100000 | 914300000 | 914500000 | 914700000 | 914900000 |

EU868 BAND:

| CHANNEL_CONF | setup_freq_0 | setup_freq_1  | Channel_1 | Channel_2 | Channel_3 | Channel_4 | Channel_5 | Channel_6 | Channel_7 | Channel_8 |
| ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
| 0 | 867500000 | 868500000 | 867100000 | 867300000 | 867500000 | 867700000 | 867900000 | 868100000 | 868300000 | 868500000 |
| 1 | 869100000 | 870100000 | 868700000 | 868900000 | 869100000 | 869300000 | 869500000 | 869700000 | 869900000 | 870100000 |

### Examples

```
          sudo bash LoRa-GW-Channel-Setup.sh 0 US915
          sudo bash LoRa-GW-Channel-Setup.sh 1 EU868
```

## Continuous-Channel-Switch.sh ##

This script is used to modify the channel setup periodically for scanning purposes. 

### Prerequisites

Make sure to follow these steps:

1. Place this script inside the /lora/packet_forwarder/lora_pkt_fwd/ folder where global_conf.json file is located. 
2. Configure a **service** for the packet forwarder with the **restart** option. If you used the `LoRa-GW-Installer.sh` script, this is already done.

### Usage:
```
      sudo bash Continuous-Channel-Switch.sh [OPTIONS]

[Options]:
	-t/--time_interval
		Time interval between each channel switch. [NUM][s/m/h/d] (seconds, minutes, hours or days)
        	-t=1m (for one minute interval)
                -t=3h (for three hour interval)
                --time_interval=7d (for seven days interval)

	 -b/--band
		LoRaWAN region / frequency band that the gateway is operating in.
                -b=US915 (US915 region, 902-928MHz)
                -band=EU868 (EU868 region, 863-870MHz)

	 -c/--channel_conf
		List of channel configurations. '0': channels 0-7, '1': channels 8-15, ...
                -c=0,1,5,3
                --channel_conf=0,1,2,3,4,5,6,7

	 -s/--gateway_service
		Service that runs packet_forwarder and needs to be restarted to effect the changes of new channel setup, default service name is 'lorawan-gateway' if no parameter is set.
                -s=my_own_gateway_service
                --gateway_service=my_own_gateway_service
```  
### Examples

This example command goes though every set of channel switching every 3 hours:

```
        sudo bash Continous-Channel-Switch.sh -t=3h -c=0,1,2,3,4,5,6,7 -b=US915
```        
More examples:

```
      sudo bash Continuous-Channel-Switch.sh -t=1d -c=0,1,2,3 -b=US915
      sudo bash Continuous-Channel-Switch.sh -t=5h -c=0,1 -s=my-own-gw-service -b=EU868
```
