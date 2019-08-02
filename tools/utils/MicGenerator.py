import lorawanwrapper.LorawanWrapper as LorawanWrapper
import re

def generate_mic(message, key):    
    if key is not None:
        search = re.search(b'(.*)"data"\s?:\s?"(.*?)"(.*)', message)
        message = search.group(1) + b'"data":"' + LorawanWrapper.generateValidMIC(search.group(2),key) + b'"' + search.group(3)

    return message