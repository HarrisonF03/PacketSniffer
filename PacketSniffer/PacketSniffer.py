import ipaddress
import socket
import struct
import sys
import argparse

parser = argparse.ArgumentParser(description='Network packet sniffer') # Create a parser object this will handle the arguments
parser.add_argument('--ip', help='IP address to sniff on', required=True) # Add an argument to the parser object to specify the IP address to sniff on
opts = parser.parse_args() # Parse the arguments

class Packet:                   # Packet class
    def __init__(self, data):
        self.packet = data      # Packet data
        header = struct.unpack('<BBHHHBBH4s4s', self.packet[0:20]) # Unpack the packet header into a tuple, 
                                                                   #(B = 1 byte) (H = 2 bytes) and (4s = 4 bytes)
                                                                   # The header is 20 bytes long
        
        self.ver = header[0] >> 4 # Version - 4 bits
                                  # Version is the first 4 bits of this byte so we use the >> operator to shift the bits to the right giving us the first 4 bits
        
        self.ihl = header[0] & 0xF # Internet Header Length - 4 bits
                                   # IHL is the last 4 bits of this byte so we use the & operator to perform a bitwise AND operation with the first byte and the mask 0xF (1111) which gives us the last 4 bits
                                   # Example: (header[0])01000101 & (0xF mask)00001111 = 00000101 (IHL)           
        
        self.tos = header[1] # Type of service - 1 byte
        self.totLen = header[2] # Total length - 2 bytes
        self.id = header[3] # Identification - 2 bytes
        self.off = header[4] # Flag and fragment offset - 2 bytes
        self.ttl = header[5] # Time to live - 1 byte
        self.pro = header[6] # Protocol - 1 byte
        self.check = header[7] # Header checksum - 2 bytes
        self.src = header[8] # Source address - 4 bytes
        self.dst = header[9] # Destination address - 4 bytes

        self.src_addr = ipaddress.ip_address(self.src) # Putting the source address in IP address format
        self.dst_addr = ipaddress.ip_address(self.dst) # Putting the destination address in IP address format

        self.protocol_map = {1: "ICMP"} # Dictionary to map the protocol number to the protocol name

        try: # Try to get the protocol name from the dictionary
            self.protocol = self.protocol_map[self.pro] 
        except Exception as e: # If the protocol number is not in the dictionary then set the protocol to the protocol number
            print(f'{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)

def print_header(self): # Print the packet header
    print(f'Protocol: {self.protocol}') 




def sniff(host): 
    socket_protocol = socket.IPPROTO_ICMP # Protocol number for ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol) # Create a raw socket to sniff on
    sniffer.bind((host, 0)) # Bind the socket to the host and port
    sniffer.setsockopt(socket.IPPROTO_ICMP, socket.IP_HDRINCL, 1) # Include the IP header in the packet data

    try:
        while True:
            raw_data = sniffer.recv(65535) 
            packet = Packet(raw_data)
            packet.print_header_short()
    except KeyboardInterrupt:
        print('Exiting...')
        sys.exit(1)


if __name__ == '__main__': 
    sniff() 