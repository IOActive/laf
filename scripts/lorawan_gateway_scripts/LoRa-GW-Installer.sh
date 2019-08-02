#!/bin/bash

echo " "
echo "======== LoRa Gateway installer ========"
echo "........ Version 1.1 2019-04-19 ........"
echo "........ sebascheibe@github.com ........"
echo "========================================"
echo " "

pf_repository="https://github.com/Lora-net/packet_forwarder.git"
lg_repository="https://github.com/Lora-net/lora_gateway.git"
localFolder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd)"

echo "Running installer in " $localFolder
mkdir -p $localFolder/lora

echo "'lora' folder created. Cloning Git repositories..."
git clone $pf_repository ./lora/packet_forwarder
git clone $lg_repository ./lora/lora_gateway
echo "Git checkout done."

echo " "
echo "Compiling lora_gateway..."
eval "cd $localFolder/lora/lora_gateway"
eval "sudo make > /dev/null"
echo "Compiling packet_forwarder..."
eval "cd $localFolder/lora/packet_forwarder"
eval "sudo make > /dev/null"
echo "Compiling done."
eval "cd $localFolder"
echo " "
echo "------ Configuration ------"
echo " "
echo "Choose LoRa Concentrator from list:"
echo "<1> iC980A-SPI"
echo "<2> RHF0M301-SPI"
echo "<3> RAK831-SPI"
echo "<4> Another one. Manual setup required."

read -n1 -p "Please enter number: " concentrator_id
echo " "
echo " "
case $concentrator_id in
  1) echo "------ Setting up for iC980A-SPI concentrator ------"
echo '#!/bin/bash' > ./lora/start_lora_gateway.sh
echo 'echo "Reset LoRa Gateway Concentrator iC980A-SPI"' >> ./lora/start_lora_gateway.sh
echo 'while true; do' >> ./lora/start_lora_gateway.sh
echo '	sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh start 18' >> ./lora/start_lora_gateway.sh
echo '	echo "reset Pin 18 High"' >> ./lora/start_lora_gateway.sh
echo '	sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '	sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh stop 18' >> ./lora/start_lora_gateway.sh
echo '	echo "reset Pin 18 Low"' >> ./lora/start_lora_gateway.sh
echo '	sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '	echo "Start Packet Forwarder..."' >> ./lora/start_lora_gateway.sh
echo '	cd '$localFolder'/lora/packet_forwarder/lora_pkt_fwd/' >> ./lora/start_lora_gateway.sh
echo '	./lora_pkt_fwd' >> ./lora/start_lora_gateway.sh
echo "done" >> ./lora/start_lora_gateway.sh;;
  2) echo "------ Setting up for RHF0M301-SPI concentrator ------"
echo '#!/bin/bash' > ./lora/start_lora_gateway.sh
echo 'echo "Reset LoRa Gateway Concentrator RHF0M301-SPI"' >> ./lora/start_lora_gateway.sh
echo 'while true; do' >> ./lora/start_lora_gateway.sh
echo '	sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh start 7' >> ./lora/start_lora_gateway.sh
echo '	echo "reset Pin 7 High"' >> ./lora/start_lora_gateway.sh
echo '	sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '	sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh stop 7' >> ./lora/start_lora_gateway.sh
echo '	echo "reset Pin 7 Low"' >> ./lora/start_lora_gateway.sh
echo '	sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '	echo "Start Packet Forwarder..."' >> ./lora/start_lora_gateway.sh
echo '	cd '$localFolder'/lora/packet_forwarder/lora_pkt_fwd/' >> ./lora/start_lora_gateway.sh
echo '	./lora_pkt_fwd' >> ./lora/start_lora_gateway.sh
echo "done" >> ./lora/start_lora_gateway.sh;;
  3) echo "------ Setting up for RAK831-SPI concentrator ------"
echo '#!/bin/bash' > ./lora/start_lora_gateway.sh
echo 'echo "Reset LoRa Gateway Concentrator RAK831-SPI"' >> ./lora/start_lora_gateway.sh
echo 'while true; do' >> ./lora/start_lora_gateway.sh
echo '	sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh start 17' >> ./lora/start_lora_gateway.sh
echo '	echo "reset Pin 17 High"' >> ./lora/start_lora_gateway.sh
echo '	sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '	sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh stop 17' >> ./lora/start_lora_gateway.sh
echo '	echo "reset Pin 17 Low"' >> ./lora/start_lora_gateway.sh
echo '	sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '	echo "Start Packet Forwarder..."' >> ./lora/start_lora_gateway.sh
echo '	cd '$localFolder'/lora/packet_forwarder/lora_pkt_fwd/' >> ./lora/start_lora_gateway.sh
echo '	./lora_pkt_fwd' >> ./lora/start_lora_gateway.sh
echo "done" >> ./lora/start_lora_gateway.sh;;
  *) echo "------ Manual setup ------"
echo "Name of LoRa concentrator: "
read concentrator_name
echo "GPIO pin of Raspberry PI where concentrator reset pin is connected to: "
read reset_pin
echo "------ Setting up for "$concentrator_name" concentrator ------"
echo '#!/bin/bash' > ./lora/start_lora_gateway.sh
echo 'echo "Reset LoRa Gateway Concentrator '$concentrator_name'"' >> ./lora/start_lora_gateway.sh
echo 'while true; do' >> ./lora/start_lora_gateway.sh
echo '  sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh start '$reset_pin >> ./lora/start_lora_gateway.sh
echo '  echo "reset Pin '$reset_pin' High"' >> ./lora/start_lora_gateway.sh
echo '  sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '  sudo '$localFolder'/lora/lora_gateway/reset_lgw.sh stop '$reset_pin >> ./lora/start_lora_gateway.sh
echo '  echo "reset Pin '$reset_pin' Low"' >> ./lora/start_lora_gateway.sh
echo '  sleep 0.1' >> ./lora/start_lora_gateway.sh
echo '  echo "Start Packet Forwarder..."' >> ./lora/start_lora_gateway.sh
echo '  cd '$localFolder'/lora/packet_forwarder/lora_pkt_fwd/' >> ./lora/start_lora_gateway.sh
echo '  ./lora_pkt_fwd' >> ./lora/start_lora_gateway.sh
echo "done" >> ./lora/start_lora_gateway.sh;;
esac

echo " "
echo "Choose frequency band / region of Gateway:"
echo "<1> US915"
echo "<2> EU868"

read -n1 -p "Please enter number: " band
echo " "
echo " "
case $band in
  1) echo "------ Setting up US915 region ------"
eval "sudo cp $localFolder/lora/packet_forwarder/lora_pkt_fwd/cfg/global_conf.json.US902.basic $localFolder/lora/packet_forwarder/lora_pkt_fwd/global_conf.json"
eval 'sudo ex $localFolder/lora/packet_forwarder/lora_pkt_fwd/global_conf.json << EOEX
/^        }\n/,/^    "gateway_conf": {/c
	},
        "tx_lut_0": {
                /* TX gain table, index 0 */
                "pa_gain": 0,
                "mix_gain": 8,
                "rf_power": -6,
                "dig_gain": 3
        },
        "tx_lut_1": {
                /* TX gain table, index 1 */
                "pa_gain": 0,
                "mix_gain": 10,
                "rf_power": -3,
                "dig_gain": 3
        },
        "tx_lut_2": {
                /* TX gain table, index 2 */
                "pa_gain": 0,
                "mix_gain": 9,
                "rf_power": 0,
                "dig_gain": 0
        },
        "tx_lut_3": {
                /* TX gain table, index 3 */
                "pa_gain": 0,
                "mix_gain": 12,
                "rf_power": 3,
                "dig_gain": 0
        },
        "tx_lut_4": {
                /* TX gain table, index 4 */
                "pa_gain": 1,
                "mix_gain": 8,
                "rf_power": 6,
                "dig_gain": 2
        },
	"tx_lut_5": {
                /* TX gain table, index 5 */
                "pa_gain": 1,
                "mix_gain": 9,
                "rf_power": 10,
                "dig_gain": 0
        },
        "tx_lut_6": {
                /* TX gain table, index 6 */
                "pa_gain": 1,
                "mix_gain": 11,
                "rf_power": 11,
                "dig_gain": 2
        },
        "tx_lut_7": {
                /* TX gain table, index 7 */
                "pa_gain": 1,
                "mix_gain": 11,
                "rf_power": 12,
                "dig_gain": 1
        },
        "tx_lut_8": {
                /* TX gain table, index 8 */
                "pa_gain": 1,
                "mix_gain": 11,
                "rf_power": 13,
                "dig_gain": 0
        },
        "tx_lut_9": {
                /* TX gain table, index 9 */
                "pa_gain": 1,
                "mix_gain": 12,
                "rf_power": 14,
                "dig_gain": 1
        },
        "tx_lut_10": {
                /* TX gain table, index 10 */
                "pa_gain": 2,
                "mix_gain": 8,
                "rf_power": 16,
                "dig_gain": 0
        },
        "tx_lut_11": {
                /* TX gain table, index 11 */
                "pa_gain": 2,
                "mix_gain": 12,
                "rf_power": 20,
                "dig_gain": 2
        },
        "tx_lut_12": {
                /* TX gain table, index 11 */
                "pa_gain": 2,
                "mix_gain": 14,
                "rf_power": 23,
                "dig_gain": 2
        },
        "tx_lut_13": {
                /* TX gain table, index 11 */
                "pa_gain": 2,
                "mix_gain": 15,
                "rf_power": 25,
                "dig_gain": 0
        },
        "tx_lut_14": {
                /* TX gain table, index 11 */
                "pa_gain": 3,
                "mix_gain": 11,
                "rf_power": 26,
                "dig_gain": 3
                },
        "tx_lut_15": {
                /* TX gain table, index 11 */
                "pa_gain": 3,
                "mix_gain": 10,
                "rf_power": 27,
                "dig_gain": 2
        }
    },

    "gateway_conf": {
.
w!
q
EOEX'
;;
  2) echo "------ Setting up EU868 region ------"
eval "sudo cp $localFolder/lora/packet_forwarder/lora_pkt_fwd/cfg/global_conf.json.PCB_E286.EU868.basic $localFolder/lora/packet_forwarder/lora_pkt_fwd/global_conf.json"
;;
  *) echo "------ Input error. Not setting up Gateway region ------";;
esac

echo " "
echo '{' > $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '/* Put there parameters that are different for each gateway (eg. pointing one gateway to a test server while the others stay in production) */' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '/* Settings defined in global_conf will be overwritten by those in local_conf */' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '	"gateway_conf": {' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '		"gateway_ID": "A0A0A0A0A0A0A0A0",' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '		"server_address": "localhost",' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '		"serv_port_up": 1680,' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '		"serv_port_down": 1680' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '	}' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo '}' >> $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json

eval "cd $localFolder/lora/packet_forwarder/lora_pkt_fwd"
eval "sudo ./update_gwid.sh ./local_conf.json"




echo " "
echo "IP/URL of LoRaWAN-Server: "
read lw_server
sudo sed -i '/"server_address"/c\\t\t"server_address": "'$lw_server'",' $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo "LoRaWAN-Server UP Port: "
read lw_up
sudo sed -i '/"serv_port_up"/c\\t\t"serv_port_up": '$lw_up',' $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json
echo "LoRaWAN-Server DOWN Port: "
read lw_down
sudo sed -i '/"serv_port_down"/c\\t\t"serv_port_down": '$lw_down'' $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json

eval "sudo ln -s $localFolder/lora/start_lora_gateway.sh /usr/local/bin/gw_start -f"
eval "sudo chmod +x $localFolder/lora/start_lora_gateway.sh"
echo " "
eval "sudo cp $localFolder/lora/start_lora_gateway.sh /usr/bin/start_lora_gateway.sh"
eval "sudo chmod +x /usr/bin/start_lora_gateway.sh"

echo "Creating lorawan-gateway.service file in /etc/systemd/system/"
echo "[Unit]" > /etc/systemd/system/lorawan-gateway.service
echo "Description=LoRaWAN Gateway Service" >> /etc/systemd/system/lorawan-gateway.service
echo "" >> /etc/systemd/system/lorawan-gateway.service
echo "[Service]" >> /etc/systemd/system/lorawan-gateway.service
echo "ExecStart=/bin/bash /usr/bin/start_lora_gateway.sh" >>  /etc/systemd/system/lorawan-gateway.service
echo "" >> /etc/systemd/system/lorawan-gateway.service
echo "[Install]" >> /etc/systemd/system/lorawan-gateway.service
echo "WantedBy=multi-user.target" >> /etc/systemd/system/lorawan-gateway.service
eval "sudo chmod +x /etc/systemd/system/lorawan-gateway.service"
eval "sudo systemctl enable lorawan-gateway.service"
echo " "
echo "========================================================================="
echo " "
echo " SETUP DONE! CONGRATULATIONS! :)"
echo " To start the LoRa Gateway please run the following command in a terminal:"
echo " "
echo "  > gw_start"
echo " "
echo " or use the created service to run it in the background:"
echo " "
echo "  > sudo service lorawan-gateway start"
echo "  > sudo service lorawan-gateway stop"
echo "  > sudo service lorawan-gateway status"
echo " "
echo " Configuration files are located in:"
echo "  /usr/bin/start_lora_gateway.sh [SERVICE]"
echo "  $localFolder/lora/start_lora_gateway.sh [TERMINAL APP]"
echo "  /etc/systemd/system/lorawan-gateway.service"
echo "  $localFolder/lora/packet_forwarder/lora_pkt_fwd/global_conf.json"
echo "  $localFolder/lora/packet_forwarder/lora_pkt_fwd/local_conf.json"
echo " "
echo "========================================================================="
