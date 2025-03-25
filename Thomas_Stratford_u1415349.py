from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()

mac_table = {
    "10.0.0.1": "00:00:00:00:00:01",
    "10.0.0.5": "00:00:00:00:00:05"
}

def _handle_PacketIn(event):
    packet = event.parsed
    if packet.type == packet.ARP_TYPE:
        arp_pkt = packet.payload
        if arp_pkt.opcode == arp_pkt.REQUEST and str(arp_pkt.protodst) == "10.0.0.10":
            log.info("Handling ARP for 10.0.0.10")
            arp_reply = of.ofp_packet_out()
            arp_reply.data = packet
            arp_reply.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(arp_reply)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("POX Controller Running...")
