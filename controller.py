# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet, arp, icmp

from PPP.functions import parse_Packet, print_Packet
import os

from rules import time_rule

class SimpleSwitch13(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        match = parser.OFPMatch()

        # delete flows that match anything ( aka delete all flows )
        self.delete_flows(datapath, match);

        # add a flow between the switch and the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0, 0)


   
    def add_flow(self, datapath, priority, match, actions, idle_timeout, hard_timeout, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        table_id = 100
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                table_id=table_id, idle_timeout=idle_timeout,  hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def delete_flows(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        table_id = 100
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, match=match, table_id=table_id)
        datapath.send_msg(mod)
         
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg  


        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        added_flow = 'False'                              

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id      
        self.mac_to_port.setdefault(dpid, {})
       


        in_port = msg.match['in_port']
        in_phy_port = msg.match['in_phy_port']
        vlan_id = msg.match['vlan_vid'] - 4096; 
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst
        eth_type = eth.ethertype
   
        Packet = parse_Packet.Parser(msg.data)
        print_Packet.Printer(Packet)

        
        WIN_SURF_MAC = '00:15:5d:55:8a:06'
        if dst == WIN_SURF_MAC  or src == WIN_SURF_MAC:
            hard_timeout = 0  # never times out
        else:
            hard_timeout = 30 # default 30 seconds timeout for all other flows
        
        idle_timeout = 0      # never times out

        switch_IP_addresses = ['0a012c14', '0a012c0a']

        switchIsTarget = False
        if Packet.ethertype.hex() == '0806':
            if Packet.ARP.target_ip_address.hex() in switch_IP_addresses:
                switchIsTarget = True
        elif Packet.ethertype.hex() == '0800':
            if Packet.IPv4.destination_ip_address.hex() in switch_IP_addresses:
                switchIsTarget = True

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        elif switchIsTarget:
            out_port = ofproto.OFPP_NORMAL
        else:
            out_port = ofproto.OFPP_FLOOD
        

        actions = [parser.OFPActionOutput(out_port)]

        arguments = {'in_port': in_port, 'eth_src': src} 
        
        eth_type = int.from_bytes(Packet.ethertype, 'big');
        arguments['eth_type'] = eth_type 

        match = parser.OFPMatch(**arguments)

        self.add_flow(datapath,1,match,actions,idle_timeout,hard_timeout)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
       

def send_switch_ARP_reply( self, datapath, request_pkt, in_port, vlan_id ): 
    hard_timeout = 30;
    remote_switch_MAC = '5c:b9:01:20:0f:80'
    remote_switch_IP = '10.1.44.20'

    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    
    eth = request_pkt.get_protocols(ethernet.ethernet)[0]
    src = eth.src
    dst = eth.dst

    request_arp = request_pkt.get_protocols(arp.arp)[0]
    
    if request_arp.dst_ip != remote_switch_IP:
        return;

    arguments = {'eth_src': remote_switch_MAC, 'eth_type': 0x806 } 
        
    if eth.ethertype == 0x8100:
        arguments['vlan_vid'] = vlan_id

    match = parser.OFPMatch(**arguments)

    actions = [parser.OFPActionOutput(in_port)]

    self.add_flow(datapath,1,match,actions,0,hard_timeout)

    arp_resp = packet.Packet()

    arp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                          dst=src, src=remote_switch_MAC))

    arp_resp.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                          src_mac=remote_switch_MAC, 
                          src_ip=remote_switch_IP,
                          dst_mac=request_arp.src_mac,
                          dst_ip=request_arp.src_ip))

    arp_resp.serialize()

    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
    
    datapath.send_msg(out)
'''
def send_switch_ICMP_reply( self, datapath, request_pkt, in_port ):
    remote_switch_MAC = '5c:b9:01:20:0f:80'
    remote_switch_IP = '10.1.44.20'

    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    
    eth = request_pkt.get_protocols(ethernet.ethernet)[0]
    src = eth.src
    dst = eth.dst

    request_icmp = request_pkt.get_protocols(icmp.icmp)[0]
    
    if request_icmp.dst_ip != remote_switch_IP:
        return;

    actions = [parser.OFPActionOutput(in_port)]

    icmp_resp = packet.Packet()

    icmp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                          dst=src, src=remote_switch_MAC))

    icmp_resp.add_protocol(


    icmp_resp.serialize()

    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=icmp_resp)
    
    datapath.send_msg(out)
'''

