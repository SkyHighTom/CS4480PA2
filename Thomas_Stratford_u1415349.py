# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

log = core.getLogger()

mac_table = {
    "10.0.0.1": "00:00:00:00:00:01",
    "10.0.0.5": "00:00:00:00:00:05"
}

def _handle_PacketIn(event):
    packet = event.parsed

    if packet.type == packet.ARP_TYPE:
        # Handle ARP
        arp_pkt = packet.payload
        if arp_pkt.opcode == arp_pkt.REQUEST and str(arp_pkt.protodst) == "10.0.0.10":
            arp_reply = of.ofp_packet_out()
            arp_reply.data = packet
            arp_reply.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(arp_reply)

    elif packet.type == packet.IP_TYPE:
        ip_pkt = packet.payload
        if ip_pkt.protocol == ip_pkt.ICMP_PROTOCOL:
            # Install flow for ICMP packets
            msg = of.ofp_flow_mod()
            msg.match.nw_proto = 1
            msg.match.dl_type = 0x0800  # IP
            msg.match.nw_dst = "10.0.0.10"
            msg.actions.append(of.ofp_action_nw_addr.set_dst("10.0.0.5"))
            msg.actions.append(of.ofp_action_output(port=2))
            event.connection.send(msg)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
