# Import POX libraries
from pox.core import core  # Main POX object
import pox.openflow.libopenflow_01 as of  # OpenFlow 1.0 library
import pox.lib.packet as pkt  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr  # Address types
import pox.lib.util as poxutil  # Utility functions
import pox.lib.revent as revent  # Event library
import pox.lib.recoco as recoco  # Multitasking library

# Create a logger
log = core.getLogger()

class LoadBalancerController:
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.arp_table = {}
        self.round_robin = {
            IPAddr("10.0.0.5"): [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")],
            IPAddr("10.0.0.6"): [IPAddr("10.0.0.6"), IPAddr("10.0.0.5")]
        }
        self.flow_rules_installed = set()

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        
        if packet.type == pkt.ethernet.ARP_TYPE:
            self._handleArp(event, packet)
        elif packet.type == pkt.ethernet.IP_TYPE:
            self._handleIP(event, packet)
    
    def _handleArp(self, event, packet):
        arp_packet = packet.payload
        vip = arp_packet.protodst
        log.info(f"Handling ARP for {vip}")
        
        if vip in self.round_robin:
            backend_ip = self.get_next_backend(vip)
            mac_address = EthAddr(f"00:00:00:00:00:0{str(backend_ip)[-1]}")
            self.arp_table[vip] = mac_address
            self.send_arp_reply(event, packet, mac_address)

    def send_arp_reply(self, event, packet, mac_address):
        arp_reply = pkt.arp()
        arp_reply.hwsrc = mac_address
        arp_reply.hwdst = packet.src
        arp_reply.opcode = pkt.arp.REPLY
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.ARP_TYPE  
        ether.dst = packet.src
        ether.src = mac_address
        ether.payload = arp_reply

        packet_out = of.ofp_packet_out()
        packet_out.data = ether.pack()
        packet_out.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(packet_out)

    def _handleIP(self, event, packet):
        ip_packet = packet.payload
        vip = ip_packet.dstip
        log.info(f"Handling IP packet for {vip}")
        
        if vip in self.round_robin:
            backend_ip = self.get_next_backend(vip)
            self.install_flow_rule(event, ip_packet.srcip, backend_ip)
            self.forward_packet(event, packet, backend_ip)

    def install_flow_rule(self, event, client_ip, backend_ip):
        if backend_ip not in self.flow_rules_installed:
            msg = of.ofp_flow_mod()
            msg.match.nw_src = client_ip
            msg.match.nw_dst = backend_ip
            msg.actions.append(of.ofp_action_nw_addr.set_dst(backend_ip))
            event.connection.send(msg)
            self.flow_rules_installed.add(backend_ip)

    def forward_packet(self, event, packet, backend_ip):
        ip_packet = packet.payload
        ip_packet.dstip = backend_ip
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.IP_TYPE
        ether.src = packet.src
        ether.dst = EthAddr(f"00:00:00:00:00:0{str(backend_ip)[-1]}")
        ether.payload = ip_packet

        packet_out = of.ofp_packet_out()
        packet_out.data = ether.pack()
        packet_out.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(packet_out)

    def get_next_backend(self, vip):
        backend_list = self.round_robin[vip]
        backend = backend_list.pop(0)
        backend_list.append(backend)  # Rotate backend selection
        return backend

@poxutil.eval_args
def launch():
    def _go_up(event):
        log.info("Connection up")
        LoadBalancerController(event.connection)
    core.addListenerByName("ConnectionUp", _go_up)
