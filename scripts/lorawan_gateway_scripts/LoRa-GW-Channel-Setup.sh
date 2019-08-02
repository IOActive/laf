#!/bin/bash

echo " "
echo "====== LoRa Gateway Channel Setup ======"
echo "........ Version 1.1 2019-04-19 ........"
echo "........ sebascheibe@github.com ........"
echo "========================================"
echo ""

# setup_id setup_freq_0 setup_freq_1 -> Channel_1 Channel_2 Channel_3 Channel_4 Channel_5 Channel_6 Channel_7 Channel_8
#    0	    902700000    903400000   -> 902300000 902500000 902700000 902900000 903100000 903300000 903500000 903700000
#    1      904300000    905000000   -> 903900000 904100000 904300000 904500000 904700000 904900000 905100000 905300000
#    2      905900000    906600000   -> 905500000 905700000 905900000 906100000 906300000 906500000 906700000 906900000
#    3      907500000    908200000   -> 907100000 907300000 907500000 907700000 907900000 908100000 908300000 908500000
#    4      909100000    909800000   -> 908700000 908900000 909100000 909300000 909500000 909700000 909900000 910100000
#    5      910700000    911400000   -> 910300000 910500000 910700000 910900000 911100000 911300000 911500000 911700000
#    6      912300000    913000000   -> 911900000 912100000 912300000 912500000 912700000 912900000 913100000 913300000
#    7      913900000    914600000   -> 913500000 913700000 913900000 914100000 914300000 914500000 914700000 914900000

# EU868 BAND:
# setup_id setup_freq_0 setup_freq_1 -> Channel_1 Channel_2 Channel_3 Channel_4 Channel_5 Channel_6 Channel_7 Channel_8
#    0	    867500000    868500000   -> 867100000 867300000 867500000 867700000 867900000 868100000 868300000 868500000
#    1      869100000    870100000   -> 868700000 868900000 869100000 869300000 869500000 869700000 869900000 870100000


localFolder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd)"

if ! [[ $2 == 'US915' ]] && ! [[ $2 == 'EU868' ]] || [[ $1 == '-h' ]] || [[ $1 == '--help' ]]; then
echo "Running in " $localFolder
echo "Please verify that the script runs inside the /lora/packet_forwarder/lora_pkt_fwd/ folder where global_conf.json file is located!"
echo " "
echo "run script with following parameters: sudo bash LoRa-GW-Channel-Setup.sh [CHANNEL_CONF] [BAND_REGION]"
echo "[CHANNEL_CONF]: integer value 0 1 2 ..."
echo "[BAND_REGION]: US915 or EU868 currently supported"
echo "Example: sudo bash LoRa-GW-Channel-Setup.sh 0 US915"
exit 1
fi


if [[ $2 == 'US915' ]]; then
    # Only allow numeric values of '0' to '7' as valid input:
    channel_regex='^[0-7]$'
elif [[ $2 == 'EU868' ]]; then
    # Only allow numeric values of '0' to '1' as valid input:
    channel_regex='^[0-1]$'
fi

if [[ $1 =~ $channel_regex ]]; then
    echo "Setting Gateways LoRa channels with parameter $1 for $2 region"
    setup_id=$1
else
  if [[ $2 == 'US915' ]]; then
    while :; do
    
        echo "Choose LoRa Channel band:"
        echo "<0> 902.3 to 903.7MHz"
        echo "<1> 903.9 to 905.3MHz"
        echo "<2> 905.5 to 906.9MHz"
        echo "<3> 907.1 to 908.5MHz"
        echo "<4> 908.7 to 910.1MHz"
        echo "<5> 910.3 to 911.7MHz"
        echo "<6> 911.9 to 913.3MHz"
        echo "<7> 913.5 to 914.9MHz"
      read -n1 -p "Please enter number (0-7):" setup_id
      [[ $setup_id =~ ^[0-9]+$ ]] || { echo ""; echo "Enter a valid number!"; continue; }
      if ((setup_id >= 0 && setup_id <= 7)); then
        break
      else
        echo ""
        echo "Number out of range, try again!"
      fi
    done
  elif [[ $2 == 'EU868' ]]; then
    while :; do
    
        echo "Choose LoRa Channel band:"
        echo "<0> 867.1 to 868.5MHz"
        echo "<1> 868.7 to 870.1MHz"
      read -n1 -p "Please enter number (0-1):" setup_id
      [[ $setup_id =~ ^[0-9]+$ ]] || { echo ""; echo "Enter a valid number!"; continue; }
      if ((setup_id >= 0 && setup_id <= 1)); then
        break
      else
        echo ""
        echo "Number out of range, try again!"
      fi
    done
  fi
fi

if [[ $2 == 'US915' ]]; then
setup_freq_0=$((902700000+$setup_id*1600000))
setup_freq_1=$(($setup_freq_0+700000))
elif [[ $2 == 'EU868' ]]; then
setup_freq_0=$((867500000+$setup_id*1600000))
setup_freq_1=$(($setup_freq_0+1000000))
fi

echo ""
echo "Setting up global_conf.json with following frequency parameters: $setup_freq_0 and $setup_freq_1"

# update line 9 with new setup_freq_0 parameter, IMPORTANT: adjust line number for E336.EU868 to 20
sed -i '9s/.*/            "freq": '$setup_freq_0',/' global_conf.json
# update line 18 with new setup_freq_1 parameter, IMPORTANT: adjust line number for E336.EU868 to 30
sed -i '18s/.*/            "freq": '$setup_freq_1',/' global_conf.json

echo "Gateway configured for LoRa Channels $((8*$setup_id)) ($(($setup_freq_0-400000))Hz) to $((8*$setup_id + 7)) ($(($setup_freq_1+300000))Hz)."

echo ""
echo "DONE! Please restart Gateway packet-forwarder to effect changes."


