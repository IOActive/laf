import json, os, logging
from auditing.db.Models import AlertType, DataCollector

if os.environ.get("ENVIRONMENT") == "DEV":
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

def print_alert(alert):
    try: 
        alert_type = AlertType.find_one_by_code(alert.type)

        message= alert_type.code + '-' + alert_type.message

        dict_parameters= json.loads(alert.parameters)

        collector= DataCollector.find_one(alert.data_collector_id)
        if collector:
            message= message.replace('{'+'collector.name'+'}', collector.name+' (ID '+str(collector.id)+')')
        else:
            message= message.replace('{'+'collector.name'+'}', str(alert.data_collector_id ))

        for param_name, param_value in dict_parameters.items():
            message= message.replace('{'+param_name+'}', str(param_value))

        message= message.replace('{'+'packet_id'+'}', str(alert.packet_id))

        message= message.replace('{'+'created_at'+'}', alert.created_at.strftime('%Y-%m-%d %H:%M'))
    
    except Exception as e:
        logging.error('Error printing alert: {0}'.format(e))
    
    logging.debug(message)