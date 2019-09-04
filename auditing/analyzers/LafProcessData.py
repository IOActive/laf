# LoRaWAN Security Framework - lafProcessData
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import argparse, sys, time, logging, os
from auditing.analyzers.printer import LafPrinter
from auditing.analyzers.bruteforcer import LafBruteforcer
from auditing.analyzers.dataanalysis import LafPacketAnalysis
from auditing.db.Models import RowProcessed, Packet, commit, rollback

# Define the number of raw packets that will be processed before writing into DB. It shoudn't be so big
PACKETS_BATCH =  10

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

def processData():
    # Save the packet ids that have to be processed by the selected modules
    starting_rows = list() 
  
    if analyze:
        analyzer_row = RowProcessed.find_one_by_analyzer("packet_analyzer")
        starting_rows.append(analyzer_row.last_row)

    if bruteforce:
        bruteforcer_row = RowProcessed.find_one_by_analyzer("bruteforcer")
        starting_rows.append(bruteforcer_row.last_row)
        
    # Get the lowest packet ID to be processed 
    first_pending_id=starting_rows[0]
    for row in starting_rows:
        if row < first_pending_id:
            first_pending_id = row

    # Jump to the next to be procesed
    first_pending_id += 1
    
    # If the user provided the start id, do some checksstart_packet_id = None
    if options.from_id is not None:
        start_packet_id = options.from_id
        if start_packet_id > first_pending_id:
            print ("Warning! You are jumping over packets that weren't processed. Last packets ID processed: ")
            if bruteforce:
                print ("Bruteforcer: %d."%(bruteforcer_row.last_row))
            if analyze:
                print ("Analyzer: %d."%(analyzer_row.last_row ))
        elif start_packet_id < first_pending_id: 
            print ("Warning! You will process twice some packets and duplicate information in DB. Last packets ID processed: ")
            if bruteforce:
                print ("Bruteforcer: %d."%(bruteforcer_row.last_row))
            if analyze:
                print ("Analyzer: %d."%(analyzer_row.last_row ))
    else:    
        start_packet_id = first_pending_id

    # Start processing in batches
    keep_iterating = True
    while keep_iterating:
        session_packets = None
        
        # Select the quantity of packets to process according to PACKES_BATCH and the limit that the user may have provided
        if options.to_id is None:

            if (start_packet_id + 2*PACKETS_BATCH) <= Packet.rows_quantity():
                session_packets = Packet.find_all_from(start_packet_id, PACKETS_BATCH)
                start_packet_id += PACKETS_BATCH

            else:
                logging.debug("No more packets to process. Sleeping a while")
                time.sleep(20)
                continue
        
        else:
            if (start_packet_id + PACKETS_BATCH) <= options.to_id:
                
                if (start_packet_id + PACKETS_BATCH) <= Packet.rows_quantity():
                    session_packets = Packet.find_all_from(start_packet_id, PACKETS_BATCH)
                    start_packet_id += PACKETS_BATCH

                else:
                    logging.debug("No more packets to process. Sleeping a while")
                    time.sleep(20)
                    continue
            
            else:
                session_packets = Packet.find_all_from(start_packet_id, options.to_id - start_packet_id + 1)
                start_packet_id += (options.to_id % PACKETS_BATCH)
                keep_iterating = False

        if session_packets is not None:
            for packet in session_packets:
                logging.debug("Using packet: %d"%(packet.id))
                # Skip packets from /{dev_eui}/up topic?

                try:
                    # If the starting packet wasn't given, check if the packet wasn't processed by each analyzer (except for the parser, which doesn't modify the DB)
                    if options.from_id is None:
                        if bruteforce and bruteforcer_row.last_row < packet.id:
                            LafBruteforcer.bruteForce(packet)
                            bruteforcer_row.last_row = packet.id

                        if analyze and analyzer_row.last_row  < packet.id:
                            LafPacketAnalysis.processPacket(packet)
                            analyzer_row.last_row = packet.id

                    # If the starting packet was given by the user, don't do any check
                    else:
                        if bruteforce:
                            LafBruteforcer.bruteForce(packet)
                            if bruteforcer_row.last_row < packet.id:
                                bruteforcer_row.last_row = packet.id

                        if analyze:
                            LafPacketAnalysis.processPacket(packet)
                            
                            if analyzer_row.last_row  < packet.id:
                                analyzer_row.last_row = packet.id
               
                except Exception as e:    
                    logging.error("Error processing packet {0}. Exception: {1}".format(packet.id ,e))
                    rollback()
                  
                if parsedata:
                    LafPrinter.printPacket(packet)

            # Commit objects in DB before starting with the next batch
            try:
                commit()
            except Exception as exc:
                logging.error("Error trying to commit after batch processing finish: {0}".format(exc))
            


def init():    
    
    global bruteforce
    bruteforce = options.bforce  

    if bruteforce:
        print ("Bruteforce module ON")
        
        # Look for sub-options
        if options.keys is not None:
            print ("- Using keys file: %s"%(options.keys))
            keysPath = options.keys

        if options.no_gen is True:
            print ("- Keys won't be generated dinamically by bruteforcer")
        
        LafBruteforcer.init(keysPath, options.no_gen)
    else:
        if options.keys is not None or options.no_gen is not None:
            print ("Bruteforce module OFF - Won't accept its suboptions")

    global parsedata
    parsedata = options.parse

    if parsedata:
        print ("DataParser module ON")
    
    global analyze
    analyze = options.analyze
    if analyze:
        print ("DataCollector module ON")

    print ("\n********************************************\n")


if __name__ == '__main__':
    try:
        print ("\n*****************************************************")
        print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
        print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
        print ("*****************************************************\n")
        
        parser = argparse.ArgumentParser(description='This script reads retrieves packets from DB and executes different sub-tools. Then, each sub-tool will save output data into the DB. See each option for more information.')
        parser.add_argument("-a", "--analyze",
                            help = "Collect and analyze different aspects from traffic. If Bruteforcer (-b) is activated, results will be corelated",
                            action="store_true",
                            default = False
                            )
        parser.add_argument("-b", "--bforce",
                            help = "Try to bruteforce the AppKeys with JoinRequests and JoinAccepts payloads",
                            action="store_true",
                            default = False
                            )
        parser.add_argument("-k", "--keys", 
                            help = '[Bruteforcer] Filepath to keys file.  If not provided, "bruteForcer/keys.txt" will be used',
                            default = "./bruteforcer/keys.txt"
                            )
        parser.add_argument("--no-gen",
                            help = "[Bruteforcer] Don't generate keys, only try keys from files",
                            action = 'store_true',
                            default = None
                            )
        parser.add_argument("-p", "--parse",
                            help= 'Parse the PHYPayload into readable information',
                            action="store_true", 
                            default=False
                            )
        parser.add_argument("--from-id",
                            help= 'Packet ID from where to start processing.',
                            default = None,
                            type = int
                            )
        parser.add_argument("--to-id",
                            help= 'Last packet ID to be processed.',
                            default = None,
                            type = int
                            )

        options = parser.parse_args()

        # Parse args and init analyzers
        init()
        
        processData()
    
    except KeyboardInterrupt:
        exit(0)