#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn' learn.)
'''

from switchyard.lib.userlib import *
import collections

class F_Table_Entry:
  
    def __init__(self, port, mac):
        self.port = port
        self.mac = mac


def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    f_table = collections.deque()

    while True:
        try:
            (timestamp, input_port, packet) = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug('In {} received packet {} on {}'.format(net.name,
                  packet, input_port))
        if packet[0].dst in mymacs:
            log_debug('Packet intended for me')

        found = False

        if packet[0].src not in [entry.mac for entry in f_table]:
            if len(f_table) == 5:
                f_table.popleft()
            f_table.append(F_Table_Entry(input_port, packet[0].src))
        else:
            for Entry in f_table:
                if Entry.mac == packet[0].src:
                    f_table.remove(Entry)
                    f_table.append(Entry)
                    break

        for Entry in f_table:
            if Entry.mac == packet[0].dst:
                Output_entry = Entry
                f_table.remove(Entry)
                f_table.append(Entry)
                net.send_packet(Output_entry.port, packet)
                found = True
                break

        if not found:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug('Flooding packet {} to {}'.format(packet,
                              intf.name))
                    net.send_packet(intf.name, packet)

    net.shutdown()
