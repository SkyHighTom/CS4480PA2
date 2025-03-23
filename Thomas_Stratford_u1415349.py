from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, icmp
from pox.lib.addresses import IPAddr, EthAddr
from collections import deque

log = core.getLogger()

class SimpleLoadBalancer(object):
    def __init__(self, vip="10.0.0.100", servers=None):
        self.vip = IPAddr(vip)
        self.servers = deque([IPAddr(ip) for ip in (servers or ["10.0.0.1", "10.0.0.2"])])
        self.mac_map = {}  # Maps IP addresses to MAC addresses
        self.next_server = {}  # Tracks the next server for each client
        core.openflow.addListeners(self)
        log.info("Load Balancer initialized with VIP %s", self.vip)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        in_port = event.port
        eth_packet = packet.find("ethernet")
        ip_packet = packet.find("ipv4")
        arp_packet = packet.find("arp")

        if arp_packet and arp_packet.opcode == arp.REQUEST and arp_packet.protodst == self.vip:
            self.handle_arp_request(event, arp_packet, in_port)
        elif ip_packet and ip_packet.dstip == self.vip:
            self.handle_icmp_request(event, ip_packet, eth_packet, in_port)

    def handle_arp_request(self, event, arp_packet, in_port):
        client_ip = arp_packet.protosrc
        client_mac = arp_packet.hwsrc

        # Assign the next server in round-robin fashion
        if client_ip not in self.next_server:
            self.next_server[client_ip] = self.servers[0]
            self.servers.rotate(-1)

        target_ip = self.next_server[client_ip]

        # Ensure we have a MAC address for the server
        if target_ip not in self.mac_map:
            log.info("Waiting for MAC address of server %s", target_ip)
            return

        target_mac = self.mac_map[target_ip]

        # Construct ARP reply
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = self.vip
        arp_reply.protodst = client_ip
        arp_reply.hwsrc = target_mac  # Respond with the server's MAC
        arp_reply.hwdst = client_mac

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = target_mac
        eth.dst = client_mac
        eth.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=in_port))
        event.connection.send(msg)

        log.info("Sent ARP reply: %s -> %s (%s)", self.vip, target_ip, target_mac)

    def handle_icmp_request(self, event, ip_packet, eth_packet, in_port):
        client_ip = ip_packet.srcip
        if client_ip not in self.next_server:
            log.warning("Client %s sent ICMP without an ARP request!", client_ip)
            return

        target_ip = self.next_server[client_ip]
        if target_ip not in self.mac_map:
            log.info("MAC for %s unknown, waiting...", target_ip)
            return

        target_mac = self.mac_map[target_ip]

        # Install flow rule for ICMP traffic
        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_proto = ipv4.ICMP_PROTOCOL
        msg.match.nw_dst = self.vip  # Intercept traffic to VIP

        # Rewrite to assigned server
        msg.actions.append(of.ofp_action_nw_addr.set_dst(target_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(target_mac))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))  # Assume direct connection

        event.connection.send(msg)
        log.info("Installed flow rule: %s -> %s (%s)", client_ip, target_ip, target_mac)

    def _handle_ConnectionUp(self, event):
        event.connection.addListeners(self)
        log.info("Switch connected: %s", event.connection)

# Start the controller
def launch():
    core.registerNew(SimpleLoadBalancer)
