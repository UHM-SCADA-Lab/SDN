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
from os_ken.controller import ofp_event, dpset
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ipv4
from datetime import datetime

import csv
import requests



class SimpleSwitch13(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset' : dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dpset = kwargs['dpset']
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        a = self.dpset.get_all()
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
        self.delete_flow(datapath, match);
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

    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        table_id = 100
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, match=match, table_id=table_id)
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
        vlan_vid = 3;
        time = datetime.now()
        current_time = time.strftime("%H:%M:%S")
        
        dash_line=75*'-'
        short_dash_line = 42*'-'
        log_format_address = '{data_type:<5}|{src_address:<17}|{dst_address:<17}|'
        log_format_data = '>> {field_name}: {field_data:<65}'
        log_format_info = '{info_1:<9}|{value_1:<9}| |{info_2:<9}|{value_2:<9}| |'

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
        else: 
            srcip = 'None' 
            dstip = 'None'
        
        
        self.logger.info(dash_line)
        lights = requests.get('http://10.1.88.5:5000')
        
        #self.logger.info(lights.json())

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dst = eth.dst
        src = eth.src
        ethtype = str(hex(eth.ethertype))[2:]
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

        # determine if request/response
        if (out_port == 24):        # destination is physical port 24 (switch)
            status = 'Request'
        elif (in_port == 24):       # source is physical port 24 (switch)
            status = 'Response'
        else:
            status = 'Unknown'

        # determine if lights on/off
        if (lights.json() == 0):
            light_status = 'Off'
        elif (lights.json() == 1):
            light_status = 'On'
        else:
            light_status = 'Error'

        # use csv table to find EthType name
        '''
        with open("../../Downloads/ieee-802-numbers-1.csv", 'r') as file:
            csvreader = csv.reader(file)
            for row in csvreader:
                print(row)
                if (row[1] == ethtype):
                    ethtype_eng = row[4]
                    break
                '''

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # check IP Protocol and create a match for IP
            #if eth.ethertype == ether_types.ETH_TYPE_IP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, #ipv4_src=srcip, ipv4_dst=dstip, 
                                        in_port=in_port, eth_src=src, vlan_vid=vlan_vid)
            added_flow = 'True'
            self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)
            '''
            elif eth.ethertype == ether_types.ETH_TYPE_8021Q:
                match = parser.OFPMatch(vlan_vid=3) 
                added_flow = 'True'
                self.add_flow(datapath, 1, match, actions, idle_timeout, hard_timeout)
            '''
            
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
        
        self.logger.info(short_dash_line)
        self.logger.info(log_format_address.format(data_type='', src_address='SOURCE', dst_address='DESTINATION'))
        self.logger.info(short_dash_line)
        self.logger.info(log_format_address.format(data_type='MAC',src_address=src, dst_address=dst))
        self.logger.info(log_format_address.format(data_type='IP',src_address=srcip, dst_address=dstip))
        self.logger.info(log_format_address.format(data_type='Port',src_address=in_port, dst_address=out_port))
        self.logger.info(short_dash_line)
        self.logger.info(log_format_data.format(field_name='VLAN ID', field_data=vlan_vid))
        self.logger.info(log_format_data.format(field_name='Flow Added?', field_data=added_flow))
        self.logger.info(log_format_data.format(field_name='Eth Type', field_data=ethtype))
        self.logger.info(log_format_data.format(field_name='Hard Timeout', field_data=hard_timeout))
        self.logger.info(log_format_data.format(field_name='Idle Timeout', field_data=idle_timeout))
        self.logger.info(log_format_data.format(field_name='Data', field_data=str(msg.data)))
        self.logger.info(log_format_data.format(field_name='Data Length', field_data=len(msg.data)))
        self.logger.info(log_format_data.format(field_name='(DEBUG) DPID', field_data=str(hex(dpid))[2:]))
        self.logger.info(log_format_data.format(field_name='Flow Instance Id', field_data=str(hex(dpid))[2]))
        self.logger.info(log_format_data.format(field_name='Switch MAC Address', field_data=str(hex(dpid))[3:]))
        self.logger.info(log_format_data.format(field_name='Time', field_data=current_time))
        self.logger.info(log_format_data.format(field_name='Request/Response?', field_data=status))
        self.logger.info(log_format_data.format(field_name='Lights On?', field_data=light_status))
        #self.logger.info(log_format_info.format(info_1='Hello',value_1='Goodbye',info_2='Stop',value_2='Go Go Go'))
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
