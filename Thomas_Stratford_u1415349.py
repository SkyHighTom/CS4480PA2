from pox.core import core
import pox.openflow.libopenflow_01 as of
from collections import deque

log = core.getLogger()

class SimpleLoadBalancer(object):
    def __init__(self, vip="10.0.0.100", servers=None):
        self.vip = vip
        self.servers = deque(servers) if servers else deque(["10.0.0.1", "10.0.0.2"])
        self.mac_map = {}  # Maps IP addresses to MAC addresses
        self.next_server = {}  # Tracks the next server for each client
        core.openflow.addListeners(self)
        log.info("Load Balancer initialized with VIP %s", self.vip)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        
        in_port = event.port
        ip_packet = packet.find("ipv4")
        arp_packet = packet.find("arp")

        if arp_packet and arp_packet.protodst == self.vip:
            log.debug("Handling ARP request for VIP: %s", self.vip)
            self.handle_arp_request(event, arp_packet, in_port)

    def handle_arp_request(self, event, arp_packet, in_port):
        client_ip = arp_packet.protosrc
        if client_ip not in self.next_server:
            self.next_server[client_ip] = self.servers[0]  # Assign next server
            self.servers.rotate(-1)  # Rotate to next server
        
        target_ip = self.next_server[client_ip]
        if target_ip in self.mac_map:
            target_mac = self.mac_map[target_ip]
        else:
            return  # If MAC address is unknown, we wait
        
        arp_reply = of.ofp_packet_out()
        arp_reply.actions.append(of.ofp_action_output(port=in_port))
        arp_reply.data = event.data
        event.connection.send(arp_reply)
        log.info("Responded to ARP request: %s -> %s (%s)", client_ip, target_ip, target_mac)

        # Install flow to forward to the correct server
        self.install_flow(event, in_port, target_ip, target_mac)

    def install_flow(self, event, in_port, target_ip, target_mac):
        # Create a flow mod to forward packets to the target MAC address
        flow_mod = of.ofp_flow_mod()
        flow_mod.match = of.ofp_match(in_port=in_port, dl_type=0x0800, nw_dst=self.vip)
        flow_mod.actions.append(of.ofp_action_dl_addr.set_dst(target_mac))
        flow_mod.actions.append(of.ofp_action_output(port=in_port))  # Send to the correct port
        
        # Send flow mod to switch
        event.connection.send(flow_mod)
        log.debug("Flow installed for %s -> %s via MAC %s", self.vip, target_ip, target_mac)

    def _handle_ConnectionUp(self, event):
        #log.info("Switch connected: %s", event.connection)
        event.connection.addListeners(self)

# Start the controller
def launch():
    core.registerNew(SimpleLoadBalancer)
