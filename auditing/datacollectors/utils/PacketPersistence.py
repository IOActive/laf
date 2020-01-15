import logging, os, json
import auditing.db.Service as db_service

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)


def save(packet_writter_message, collector_id=None):

    if len(packet_writter_message['messages']) == 0:
        logging.error("Received a MQ message from Collector ID {0} without messages: {1}".format(collector_id, packet_writter_message))
        return

    db_service.save(json.dumps(packet_writter_message))