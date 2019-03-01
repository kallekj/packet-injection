try:
    import pyshark
    import argparse
    import sys
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11,sendp,RadioTap,Dot11FCS
    from scapy.all import wireshark
    from scapy import all
    import uuid
    import struct
except:
    print("!! Failed to import dependencies... ")
    raise SystemExit


parser = argparse.ArgumentParser(
    usage="probeSniffer.py [monitor-mode-interface] [options]")
parser.add_argument(
    "interface", help='interface (in monitor mode) for capturing the packets')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
monitor_if = args.interface


def packetHandler(pkt):
        
    ssid = checkSSID(pkt)


    #rssi_val = str(pkt.radiotap.dbm_antsignal)
    #mac_address = str(pkt.wlan.ta)
    #bssid = pkt.wlan.da
    #storePkt(pkt)
    return [[pkt.wlan.ta], [pkt.radiotap.dbm_antsignal], [checkSSID(pkt)]]

def checkSSID(pkt):
    if "wlan_mgt" in pkt:
        nossid = False
        if not str(pkt.wlan_mgt.tag)[:34] == "Tag: SSID parameter set: Broadcast":
            ssid = pkt.wlan_mgt.ssid
        else:
            nossid = True
    else:
        nossid = False
        if not str(pkt[3].tag)[:34] == "Tag: SSID parameter set: Broadcast":
            ssid = pkt[3].ssid
        else:
            nossid = True

    return ssid

"""
def sendRTS(MAC1, MAC2, MAC3):
    packet2 = scapy.RadioTap()
    packet2 /= Dot11(addr1=MAC1,addr2=MAC2,
              addr3=MAC3, subtype=11,type=1)
    packet2 /= scapy.Dot11Beacon(cap="ESS", timestamp=1)
    packet2 /= scapy.Dot11EltRates(rates=[130, 132, 11, 22])
    #packet2 /= scapy.Dot11Elt(ID="DSset", info="\x03")
    #packet2 /= scapy.Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")
    #packet2 /= Dot11FCS(subtype=11, type = 1)
    packet2 /= Dot11FCS()
    sendp(packet2,iface=monitor_if,return_packets = True)
"""

def sendRTS(MAC1, MAC2, MAC3):
    millis = 615
    blob = struct.pack( "<H", millis )
    millis = struct.unpack( ">H", blob )[0]

    
    packet2 = scapy.RadioTap(present="Flags", Flags="FCS")
    packet2 /= Dot11FCS(addr1=MAC1,addr2=MAC2,
              addr3=MAC3, addr4="00:00:00:00:00:00", subtype=11,type=1, ID=millis)
    packet2 /= scapy.Dot11Beacon(cap="ESS", timestamp=1)
    packet2 /= scapy.Dot11EltRates(rates=[130, 132, 11, 22])
    #packet2 /= scapy.Dot11Elt(ID="DSset", info="\x03")
    #packet2 /= scapy.Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")
    #p = scapy.srp(packet2,iface=monitor_if, timeout=0.1)
    sendp(packet2,iface=monitor_if, inter=0.1, loop=1)



def main():


    sendRTS("80:be:05:1b:e6:aa", "b8:27:eb:da:1f:22", "ff:ff:ff:ff:ff:ff")

    
    """
    try:
        capture = pyshark.LiveCapture(interface=monitor_if, bpf_filter='type mgt subtype probe-req')
        for pkt in capture:
            ssid = checkSSID(pkt)
            if pkt.wlan.ta[1] in ["2", "6", "a", "e"]:
                print("Send packet to: {}  {}".format(pkt.wlan.ta, ssid))
                sendRTS(pkt.wlan.ta, "b8:27:eb:da:1f:22", "ff:ff:ff:ff:ff:ff")
 
                
    except KeyboardInterrupt:
        print("\n Stopping...")
        raise SystemExit

    """
    """
    try:
        capture = pyshark.LiveCapture(interface=monitor_if, bpf_filter='type ctl subtype rts')
        for pkt in capture:
            print(pkt)
        for pkt in capture:
                ssid = checkSSID(pkt)
                if pkt.wlan.ta[1] in ["2", "6", "a", "e"]:
                    print("Send packet to: {}  {}".format(pkt.wlan.ta, ssid))
                    sendRTS(pkt.wlan.ta, "b8:27:eb:da:1f:22", "ff:ff:ff:ff:ff:ff")
        
                 
                
    except KeyboardInterrupt:
        print("\n Stopping...")
        raise SystemExit
    """
if __name__ == "__main__":
    main()

