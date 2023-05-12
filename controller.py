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


class SimpleSwitch13(app_manager.OSKenApp):
    # using OpenFlow v1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        # delete all flows in the switch's flow table 100
        self.delete_all_flows( datapath );

        # add a flow between the switch and the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, 0, 0, actions=actions)


   
    def add_flow(self, datapath, priority, match, idle_timeout, hard_timeout, actions = None):
        # adds a flow based on passed parameters, actions will default to OFPP_NORMAL processing

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if actions == None:
            # default to adding flows that forward packets to the switch's normal forwarding processing
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        table_id = 100
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                table_id=table_id, idle_timeout=idle_timeout,  hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def delete_all_flows(self, datapath):
        # deletes all flows in table 100 of the switch at parameter datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        
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

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        
        src = packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0].src
            
        # should eventually be replaced by the sFlow parser
        Packet = parse_Packet.Parser(msg.data)
        #print_Packet.Printer(Packet)

        
        hard_timeout = 30 # default 30 seconds timeout for all flows
        
        idle_timeout = 0      # never times out

        arguments = {'in_port': in_port, 'eth_src': src} 
        
        eth_type = int.from_bytes(Packet.ethertype, 'big');
        arguments['eth_type'] = eth_type 

        match = parser.OFPMatch(**arguments)

        self.add_flow( datapath, 1, match, idle_timeout, hard_timeout )
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
