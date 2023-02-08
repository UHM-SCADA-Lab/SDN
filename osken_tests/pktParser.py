# File to parse information from the packet

import sys
import lights
sys.path.insert(0, "/home/pi/scada_sdn")
from johnParser.functions import print_functions

def printInfo(msg, console=True, file_path=None):
    pf = print_functions.print_functions() 
    # convert reason enum to string
    def reasonStr(reason):
        if (reason == 0):
            return "OFPR_NO_MATCH"
        elif (reason == 1):
            return "OFPR_ACTION"
        elif (reason == 2):
            return "OFPR_INVALID_TTL"
        else:
            return "Unknown"

    # get current lights status
    lightStatus = lights.lightsRequest('http://10.1.88.5:5000')

    bar_length = 100
    column_widths = [17, 13]
    msg_length_entries = ["Msg Length", msg.msg_len,'Packet length']
    data_length_entries = ["Data Length", len(msg.data), 'Packet data length']
    reason_entries = ["Reason", reasonStr(msg.reason), 'Reason why the packet is being sent']
    transaction_entries = ["Transaction ID", msg.xid, 'Transaction ID']
    table_entries = ["Table ID", msg.table_id, 'Table ID where the flow is being inserted']
    buffer_entries = ["Buffer ID", msg.buffer_id, 'ID assigned by datapath']
    vlan_entries = ["VLAN ID", msg.match['vlan_vid'], 'VLAN ID']
    in_port_entries = ["In port", msg.match['in_port'], 'Switch input port']
    in_phys_port_entries = ["In physical port", msg.match['in_phy_port'], 'Switch physical input port']
    cookie_entries = ["Cookie", msg.cookie, 'Opaque controller-issued identifier']
    lights_entries = ["Lights", lightStatus, 'Current status of lights in room']

    # print the packet info
    pf.print_bar()
    pf.print_data(column_widths=column_widths, entries=msg_length_entries, just='^')
    pf.print_data(column_widths=column_widths, entries=data_length_entries, just='^')
    pf.print_data_bar(column_widths=column_widths)
    pf.print_data(column_widths=column_widths, entries=reason_entries, just='^')
    pf.print_data(column_widths=column_widths, entries=transaction_entries, just='^')
    pf.print_data(column_widths=column_widths, entries=table_entries, just='^')
    pf.print_data(column_widths=column_widths, entries=buffer_entries, just='^')
    pf.print_data(column_widths=column_widths, entries=vlan_entries, just='^')
    pf.print_data_bar(column_widths=column_widths)
    pf.print_data(column_widths=column_widths, entries=in_port_entries, just='^')
    pf.print_data(column_widths=column_widths, entries=in_phys_port_entries, just='^')
    pf.print_data_bar(column_widths=column_widths)
    pf.print_data(column_widths=column_widths, entries=cookie_entries, just='^')
    pf.print_data(column_widths=column_widths, entries=lights_entries, just='^')
