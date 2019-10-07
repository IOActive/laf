import re
import lorawanwrapper.LorawanWrapper as LorawanWrapper 

def formatData(data):
    result = ""
    
    if data is None:
        return result
    
    else:
        search = re.search('(.*)"data":"(.*?)"(.*)', data)
        if search is not None: #means that a PHYPayload was received
            result = "Parsed data: %s\n"%(LorawanWrapper.printPHYPayload(search.group(2),None))
    
    return result