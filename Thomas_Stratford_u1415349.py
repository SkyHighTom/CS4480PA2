from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from collections import deque

log = core.getLogger()

class BasicLoadBalancer(object):
    def __init__(self, vip="10.0.0.1", servers=["10.0.0.5", "10.0.0.6"]):
        self.vip = IPAddr(vip)
        self.servers = deque(map(IPAddr, servers))  # Round-robin queue
        self.mac_map = {}  # Maps IP addresses to MAC addresses
        self.next_server = {}  # Tracks assigned servers for clients

        core.openflow.addListeners(self)
        log.info("Basic Load Balancer initialized.")

    def _handle_ConnectionUp(self, event):
        event.connection.addListeners(self)
        log.info("Switch connected.")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        # Handle ARP Requests
        arp_packet = packet.find("arp")
        if arp_packet and arp_packet.opcode == arp.REQUEST:
            self.handle_arp_request(event, arp_packet)
            return

        # Handle ICMP Requests
        ip_packet = packet.find("ipv4")
        if ip_packet and ip_packet.protocol == ipv4.ICMP_PROTOCOL:
            self.handle_icmp_request(event, ip_packet)
            return

    def handle_arp_request(self, event, arp_packet):
        src_ip = arp_packet.protosrc
        dst_ip = arp_packet.protodst
        src_mac = arp_packet.hwsrc

        # Store MAC address of requester
        self.mac_map[src_ip] = src_mac

        if dst_ip == self.vip:
            if src_ip not in self.next_server:
                self.next_server[src_ip] = self.servers[0]
                self.servers.rotate(-1)

            target_ip = self.next_server[src_ip]
            target_mac = self.mac_map.get(target_ip)

            if not target_mac:
                log.info("MAC address for %s not yet known, waiting.", target_ip)
                return

            self.send_arp_reply(event, src_ip, src_mac, target_ip, target_mac)

    def send_arp_reply(self, event, src_ip, src_mac, target_ip, target_mac):
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = target_ip
        arp_reply.protodst = src_ip
        arp_reply.hwsrc = target_mac
        arp_reply.hwdst = src_mac

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = target_mac
        eth.dst = src_mac
        eth.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

        log.info("Sent ARP reply: %s -> %s (%s)", target_ip, src_ip, target_mac)

    def handle_icmp_request(self, event, ip_packet):
        client_ip = ip_packet.srcip
        if client_ip not in self.next_server:
            return

        target_ip = self.next_server[client_ip]
        target_mac = self.mac_map.get(target_ip)

        if not target_mac:
            return

        msg = of.ofp_flow_mod()
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_proto = ipv4.ICMP_PROTOCOL
        msg.match.nw_dst = self.vip

        msg.actions.append(of.ofp_action_nw_addr.set_dst(target_ip))  # Not available in OpenFlow 1.0
        msg.actions.append(of.ofp_action_dl_addr.set_dst(target_mac))  # Not available in OpenFlow 1.0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

        event.connection.send(msg)

        log.info("Forwarding ICMP %s -> %s", client_ip, target_ip)


def launch():
    core.registerNew(BasicLoadBalancer)
