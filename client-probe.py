#!/usr/bin/python

import sys
from scapy.all import *

clientprobes = set()

def PacketHandler(pkt) :

	if pkt.haslayer(Dot11ProbeReq) :
	
		if len(pkt.info) > 0 :
			testcase = pkt.addr2 + '---' + pkt.info
			if testcase not in clientprobes :
				clientprobes.add(testcase)
				print "New Probe Found: " + pkt.addr2 + ' ' + pkt.info + "\n"	
				                                                                             
				print "     000000000                              000000000          000000000"     
				print "   00:::::::::00                          00:::::::::00      00:::::::::00"   
				print " 00:::::::::::::00                      00:::::::::::::00  00:::::::::::::00" 
				print "0:::::::000:::::::0                    0:::::::000:::::::00:::::::000:::::::0"
				print "0::::::0   0::::::0xxxxxxx      xxxxxxx0::::::0   0::::::00::::::0   0::::::0"
				print "0:::::0     0:::::0 x:::::x    x:::::x 0:::::0     0:::::00:::::0     0:::::0"
				print "0:::::0     0:::::0  x:::::x  x:::::x  0:::::0     0:::::00:::::0     0:::::0"
				print "0:::::0 000 0:::::0   x:::::xx:::::x   0:::::0 000 0:::::00:::::0 000 0:::::0"
				print "0:::::0 000 0:::::0    x::::::::::x    0:::::0 000 0:::::00:::::0 000 0:::::0"
				print "0:::::0     0:::::0     x::::::::x     0:::::0     0:::::00:::::0     0:::::0"
				print "0:::::0     0:::::0     x::::::::x     0:::::0     0:::::00:::::0     0:::::0"
				print "0::::::0   0::::::0    x::::::::::x    0::::::0   0::::::00::::::0   0::::::0"
				print "0:::::::000:::::::0   x:::::xx:::::x   0:::::::000:::::::00:::::::000:::::::0"
				print " 00:::::::::::::00   x:::::x  x:::::x   00:::::::::::::00  00:::::::::::::00"
				print "   00:::::::::00    x:::::x    x:::::x    00:::::::::00      00:::::::::00"
				print "     000000000     xxxxxxx      xxxxxxx     000000000          000000000"
				
				print "\n--------- HERE ARE SOME AP'S MO-FO  ----------------\n"
                                                                         
				counter = 1
				for probe in clientprobes:
					[client, ssid] = probe.split('---')
					print counter, client, ssid
					counter = counter + 1
				
				print "\n---------------------------------------------\n"

sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandler)

