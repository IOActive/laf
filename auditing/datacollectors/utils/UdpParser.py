def formatData(data):
    result = ""
    
    if data is None:
        return result
    
    else:
        search = re.search('(.*)"data":"(.*?)"(.*)', data)
        if search is not None: #means that a PHYPayload was received
            result = "\nParsed data: %s"%(LorawanWrapper.printPHYPayload(search.group(2),None))
    
    return result