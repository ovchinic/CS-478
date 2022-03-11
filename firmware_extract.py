#firmware_extract.py
from scapy.all import *
import sys

def main():
	packets = sniff(offline="Homework/firmware/firmware.pcap", lfilter=lambda p: "HTTP/1.1" in str(p))
											#Scans capture file for HTTP traffic
	lenFile = len(packets)					#Length of HTTP traffic list
	sys.stdout = open('download.bin', 'wb')	#Creates and opens the download.bin file
	for packet in packets[:lenFile]:		#loops through the length of packet file
	sys.stdout.write(packet.load)			#Writes each packets load to download.bin
	sys.stdout.close()						#Closes download.bin
	
if __name__ == '__main__':
	main()
