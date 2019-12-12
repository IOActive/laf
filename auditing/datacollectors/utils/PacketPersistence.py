import logging, os
import auditing.db.Service as db_service

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)


def save(packet_writter_message, dc_id=None):
    db_service.save(packet_writter_message)