import logging, os
import auditing.db.Service as db_service

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)


def save(pkt, dc_id=None):
    db_service.save(pkt)