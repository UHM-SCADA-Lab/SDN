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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

import requests



class SimpleSwitch13(app_manager.RyuApp):
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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0, 0)
        ''' 
        rest_actions = [parser.OFPActionOutput(11)]

        rest_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src='10.1.44.5', ipv4_dst='10.1.88.3') 
        
        

        self.add_flow(datapath, 0, rest_match, rest_actions, 0, 0)


         
        rest_actions = [parser.OFPActionOutput(5)]
        
        BASE = 'http://10.1.44.5:5000/'

        rest_data = requests.get(BASE + 'boolean')

        rest_out = parser.OFPPacketOut(datapath=datapath,  actions=rest_actions, data=rest_data)
        
        datapath.send_msg(rest_out)
        '''
   

    def add_flow(self, datapath, priority, match, actions, idle_timeout, hard_timeout, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        table_id = 100
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                table_id=table_id, idle_timeout=idle_timeout,  hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        added_flow = 'False'
        hard_timeout = 0
        idle_timeout = 0
        


        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
        else: 
            srcip = 'None' 
            dstip = 'None'
        

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
    
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if out_port == in_port:
            return

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, 
                                        in_port=in_port, eth_src=src)
                added_flow = 'True'
                self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)
        else:
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, in_port=in_port, eth_src=src) 
                added_flow = 'True'
                self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)
            '''
            elif eth.ethertype == ether_types.ETH_TYPE_8021Q:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_8021Q, in_port=in_port, eth_src=src) 
                added_flow = 'True'
                self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)
            '''


        dash_line=75*'-'
        log_format_address = '{data_type:<5}|{src_address:<17}|{dst_address:<17}| |{info:<8}|{value:<8}'
        log_format_info = '{info_1:<9}|{value_1:<9}| |{info_2:<9}|{value_2:<9}| |'
        
    
        self.logger.info(dash_line)
        self.logger.info(log_format_address.format(data_type='MAC',src_address=src, dst_address=dst, info='AddFlow?',value=added_flow))
        self.logger.info(log_format_address.format(data_type='IP',src_address=srcip, dst_address=dstip, info='Eth Type',value=str(hex(eth.ethertype))[2:]))
        self.logger.info(log_format_address.format(data_type='Port',src_address=in_port, dst_address=out_port, info='HardTOut',value=hard_timeout))
        self.logger.info(log_format_address.format(data_type='DPID',src_address=str(hex(dpid))[2:],dst_address='',info='IdleTOut',value=idle_timeout))
        #self.logger.info(log_format_info.format(info_1='Hello',value_1='Goodbye',info_2='Stop',value_2='Go Go Go'))



       
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
