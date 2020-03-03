#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn' learn.)
'''

import sys
import time
from datetime import datetime
from switchyard.lib.userlib import *
import SpanningTreeMessage as STM
import collections
from switchyard.lib.address import *

class F_Table_Entry:
  
    def __init__(self, port, mac):
        self.port = port
        self.mac = mac

class SpanningTreeInstance:
    
    def __init__(self, lowest_mac):

        self.my_id = EthAddr(lowest_mac)
        self.root_id = EthAddr(lowest_mac)
        self.hops_from_root = 0
        self.last_stm_received = None
        self.root_interface = None
        self.root_switch_id = None
        self.blocked_interfaces = set()
        self.last_stm_sent = None

    def am_i_root(self):
        log_debug("myid: {} and root_id : {}".format(self.my_id, self.root_id))
        if(self.my_id==self.root_id):
            return True
        else:
            return False

    def become_root(self, my_interfaces):
        mymacs = [intf.ethaddr for intf in my_interfaces]
        mymacs.sort()
        self.__init__(mymacs[0])

    def set_root(self, new_root_id):
        self.root_id = EthAddr(new_root_id)
        log_debug("{} set {} as the new root".format(self.my_id, new_root_id))


    def unblock(self, unblockee):
        if unblockee in self.blocked_interfaces:
            self.blocked_interfaces.remove(unblockee)
            log_debug("{} unblocked {}".format(self.my_id, unblockee))

    def block(self, blockee):
        log_debug("the context:".format(self))
        if self.am_i_root():
            log_debug("{} is my id and {} is root id I think, ignored request to block {}".format(
                self.my_id, self.root_id, blockee))
            return
        self.blocked_interfaces.add(blockee)
        log_debug("+===+++++++++++++++++++++++++{} blocked {}+===+++++++++++++++++++++++++".format(self.my_id, blockee))

    def __str__(self):
        return "SpanningTreeContext - root: {}, blocked: {}, root_interface: {}, rootid: {}, myid: {}".format(
            self.am_i_root(), self.blocked_interfaces, self.root_interface, self.root_id, self.my_id)



def send_my_packet(net, intf_name, pkt):

    log_debug("======in send my packet========")
    net.send_packet(intf_name, pkt)


def emitStpPackets(stp_context, interfaces, net):

    log_debug("=========emit method==========")
    now = datetime.now()

    if(not stp_context.am_i_root()):
        log_debug("=========I am NOT THE root-=========")
            
            stp_context.become_root(interfaces)
    else:
        log_debug("=========I am ROOT ========")
        if stp_context.last_stm_sent is None or (now - stp_context.last_stm_sent).seconds >= 2:

                log_debug("=========MORE THAN 2 SEC=========")
                log_debug(interfaces)
                spm = STM.SpanningTreeMessage(root_id=stp_context.my_id,
                                          switch_id=stp_context.my_id)
                
                for intf in interfaces:
                    pkt = Ethernet(src=intf.ethaddr,
                               dst="ff:ff:ff:ff:ff:ff",
                               ethertype=EtherType.SLOW) + spm
                    xbytes = pkt.to_bytes()
                    p = Packet(raw=xbytes) #THIS GIVES THE ERROR**
                    send_my_packet(net, intf.name, p)

                stp_context.last_stm_sent = datetime.now()
                return

def handle_stm(net, interfaces, stp_context, pkt, incoming_interface):
    
    stp_context.last_stm_received = datetime.now()
    log_debug("Got a STP packet")
    log_debug("coming from port: {}".format(incoming_interface))
    stm = STM.SpanningTreeMessage()
    b = pkt[1].to_bytes()
    stm.from_bytes(b)
    stm.hops_to_root += 1
    log_debug("STM2: {}".format(stm))
    log_debug("The root is {} and hops are {}".format(stm.root, stm.hops_to_root))
    log_debug(stp_context)
    

    def update_all_info_stm():
        stp_context.set_root(stm.root)
        stp_context.root_interface = incoming_interface
        stp_context.unblock(incoming_interface)
        stp_context.root_switch_id = stm.switch_id
        stp_context.hops_from_root = stm.hops_to_root
        stm.switch_id = stp_context.my_id

        for intf in interfaces:
            if intf.name == incoming_interface:
                continue
            send_my_packet(net, intf.name, pkt)


    if incoming_interface == stp_context.root_interface or stm.root < stp_context.root_id:
        log_debug("Case 1 true")
        update_all_info_stm()
        return
    elif stp_context.root_id<stm.root:
        log_debug("Case 2 true")
        stp_context.unblock(incoming_interface)
        return

    if stm.root==stp_context.root_id:
        log_debug("Case 3 true")
        if stm.hops_to_root < stp_context.hops_from_root or (stm.hops_to_root == stp_context.hops_from_root and stp_context.root_switch_id > stm.switch_id):
            log_debug("Case 3a true")
            stp_context.unblock(incoming_interface)
            stp_context.block(stp_context.root_interface)
            update_all_info_stm()
        else:
            log_debug("Case 3b true")
            stp_context.block(incoming_interface)

    return


def broadcast(net, egresses, skip, pkt):
    for intf in egresses:
        if intf.name not in skip:
            log_debug("Flooding packet {} to {}".format(packet, intf.name))
            safe_send_packet(net, intf.name, pkt)


def main(net):

    log_debug("========start==========")
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    f_table = collections.deque()

    mymacs.sort()
    log_debug("======after sort of macs========")
    stp_context = SpanningTreeInstance(mymacs[0])
    log_debug(stp_context)

    while True:

        emitStpPackets(stp_context, my_interfaces, net)

        try:
            (timestamp, input_port, packet) = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug("hi")
        log_debug(stp_context)


        log_debug('In {} received packet {} on {}'.format(net.name,
                  packet, input_port))
        
        if packet[0].dst in mymacs:
            log_debug('Packet intended for me')

        log_debug(packet[0].ethertype)
        log_debug(EtherType.SLOW)

        if packet[0].ethertype == EtherType.SLOW:
            handle_stm(net, my_interfaces, stp_context, packet, input_port)
            continue

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

        log_debug("Okay, I am flooding this to all but reciving port {} and blocked port {}".format(input_port, stp_context.blocked_interfaces))
        if not found:
            for intf in my_interfaces:
                log_debug("intf.name= {} stp_context.blocked_interfaces={} input_port:{}".format(intf.name, stp_context.blocked_interfaces, input_port))
                if input_port != intf.name and intf.name not in stp_context.blocked_interfaces:
                    log_debug('Flooding packet {} to {}'.format(packet,
                              intf.name))
                    net.send_packet(intf.name, packet)

    net.shutdown()
