import datetime, json

def init(path):
    fileName = "UDP_Packets_" + datetime.datetime.today().strftime('%Y-%m-%d_%H.%M') + ".log"
    print ("Filename is " + fileName)
    global f
    f= open(path+fileName,"a+")

def save(udp, topic= None, server=None):
    data = {}
    data['date'] = datetime.datetime.now().__str__()
    #data['udp'] = udp
    #f.write(json.dumps(data)+'\n') 

    if topic is not None and topic != "":
        data['topic'] =topic

    if server is not None and server != "":
        data['server'] = server

    data['udp'] = "%r"%(udp) 
    f.write(json.dumps(data,ensure_ascii=False)+'\n')
    f.flush()
    
def close():
    f.close()




    


