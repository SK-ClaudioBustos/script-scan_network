import scapy.all as sp
import netifaces as nt   
from prettytable import PrettyTable

def scanNetwork(target):
        '''
        we just create a arp packet, we send it and we listen the answers
        '''
        request = sp.ARP(pdst=target)
        brodcast = sp.Ether(dst="ff:ff:ff:ff:ff:ff")
        request_brodcast = brodcast / request
        answered,unanswered = sp.srp(request_brodcast,timeout = 5,verbose=False,retry=1)
        target_list = []
        for sent, received in answered:
           target_list.append({"ip": received[1].psrc,"mac": received[1].hwsrc})
        return target_list

def show(target_list):
    '''
    shows the devices connected in the network
    '''
    table = PrettyTable(["IP","MAC ADRESS"])
    for target in target_list:
        table.add_row([target["ip"],target["mac"]])
    print(table)

def main():
    '''
    with netifaces module we get the gateway ip
    '''
    gateway = nt.gateways()["default"][2][0] + "/24"
    target_list = scanNetwork(gateway)
    if len(target_list) == 0:
        print("THERE IS NOT DEVICES IN YOUR NETWORK")
    else:
        show(target_list)
    
if __name__ == "__main__":
    main()

