from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from collections import deque

log = core.getLogger()

class SimpleLoadBalancer(object):
    def __init__(self, vip="10.0.0.100", servers=None):
        self.vip = IPAddr(vip)
        self.servers = deque(servers) if servers else deque([IPAddr("10.0.0.5"), IPAddr("10.0.0.6")])
        self.mac_map = {}  # Maps IP addresses to MAC addresses
        self.next_server = {}  # Tracks the next server for each client
        core.openflow.addListeners(self)
        log.info("Load Balancer initialized with VIP %s", self.vip)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        if packet.type == ethernet.ARP_TYPE:
            arp_packet = packet.payload
            if arp_packet.opcode == arp.REQUEST:
                self.handle_arp_request(event, arp_packet)

            elif arp_packet.opcode == arp.REPLY:
                log.info("Received ARP reply from %s", arp_packet.protosrc)

            else:
                log.warning("Received unknown ARP opcode: %s", arp_packet.opcode)

    def handle_arp_request(self, event, arp_packet):
        requested_ip = arp_packet.protodst
        requesting_ip = arp_packet.protosrc
        requesting_mac = arp_packet.hwsrc

        # Store the requesting MAC address
        self.mac_map[requesting_ip] = requesting_mac

        if requested_ip == self.vip:
            if requesting_ip not in self.next_server:
                self.next_server[requesting_ip] = self.servers[0]
                self.servers.rotate(-1)

            target_ip = self.next_server[requesting_ip]
            target_mac = SERVER_MACS.get(str(target_ip))

            if not target_mac:
                log.info("MAC for %s not known yet, waiting.", target_ip)
                return

            self.send_arp_reply(event, target_ip, requesting_ip, requesting_mac)

    SERVER_MACS = {
        "10.0.0.5": EthAddr("00:00:00:00:00:05"),
        "10.0.0.6": EthAddr("00:00:00:00:00:06")
    }

    def send_arp_reply(self, event, target_ip, requesting_ip, requesting_mac):
        target_mac = self.SERVER_MACS.get(str(target_ip))  # Fetch correct MAC address
        
        if not target_mac:
            log.warning("No MAC address found for %s", target_ip)
            return

        arp_reply = arp()
        arp_reply.hwsrc = target_mac
        arp_reply.hwdst = requesting_mac
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = target_ip
        arp_reply.protodst = requesting_ip

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = requesting_mac
        ether.src = target_mac
        ether.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

        log.info("Sent ARP reply: %s -> %s (%s)", target_ip, requesting_ip, target_mac)


def launch():
    core.registerNew(SimpleLoadBalancer)
