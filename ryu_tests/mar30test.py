'''https://ryu.readthedocs.io/en/latest/developing.html'''

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls


from ryu.ofproto import ofproto_v1_0

class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    '''
    as name suggests, this handles of (openflow) packet_in messages
    the @set_ev_cls function is a decorator function (plz look up)
    it's the same thing as:
    packet_in_handler = set_ev_cls(packet_in_handler)
    aka passing a function as an argument to another function
    
    the arguments of set_ev_cls:
    
    ofp_event.EventOFPacketIn --> the first argument indicates which type of event
    this function should be called for, currently set for packet_in messages
    
    MAIN_DISPATCHER --> the second argument indicates the state of the switch,
    using 'MAIN_DISPATCHER' means the function is only called after the ending of the
    negotation (b/w RYU and the siwtch) of what to do w/ packet_in messages
    
    '''
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg                       #packet_in data structure
        dp = msg.datapath                  #datapath (switch)
        ofp = dp.ofproto                   #represent the of protocol
        ofp_parser = dp.ofproto_parser     #represent the of protocol
    
        '''
        this next line is used w/ a packet_out message to specify a switch port that you want
        to send the packet out of.
        
        OFPP_FLOOD flag indicates that the packet should be sent out on all ports
        
        We don't want to use OFPP_FLOOD
        
        first we add the source mac address to a dictionary
        
        then we check if destination mac address of packet is known,
        
        if so, we send the packet to that destination, then install a flow to avoid the
        packet_in w/ the same destination and source next time
        
        if not, we use OFPP_FLOOD, but since we jotted down the source, hopefully we won't
        use OFPP_FLOOD very often
        
        So the first time we see a packet_in, we take steps to install a flow to avoid
        the packet_in the next time we see it, but for now we use OFPP_FLOOD to figure
        out where it needs to go
        '''
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]


        '''
        the following is used to build a packet_out message, most (if not all) of the
        example programs I looked at had this unchanged save for some variable name differences
        '''

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
             data = msg.data
        
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = data)
        dp.send_msg(out)