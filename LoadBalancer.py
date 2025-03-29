from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

class LoadBalancerController(object):
    def __init__(self, connection):
        self.connection = connection
        self.virtual_gateway = IPAddr("10.0.0.10")
        self.backend_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
        self.backend_macs = [EthAddr("00:00:00:00:00:05"),
                              EthAddr("00:00:00:00:00:06")]
        self.round_robin_index = 0
        self.address_table = {}
        self.client_allocation = {}
        connection.addListeners(self)

    def _select_backend(self):
        chosen_ip = self.backend_ips[self.round_robin_index]
        chosen_mac = self.backend_macs[self.round_robin_index]
        self.round_robin_index = (self.round_robin_index + 1) % len(self.backend_ips)
        return chosen_ip, chosen_mac

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return
        src_port = event.port
        self._refresh_address_table(packet, src_port)

        if packet.type == pkt.ARP_TYPE:
            arp_payload = packet.payload
            if arp_payload.opcode == pkt.arp.REQUEST:
                if arp_payload.protodst == self.virtual_gateway:
                    client_ip = arp_payload.protosrc
                    if client_ip in self.client_allocation:
                        target_ip, target_mac = self.client_allocation[client_ip]
                        log.info("Client %s reuses backend %s", client_ip, target_ip)
                    else:
                        target_ip, target_mac = self._select_backend()
                        self.client_allocation[client_ip] = (target_ip, target_mac)
                        log.info("New client %s assigned backend %s", client_ip, target_ip)
                    self._dispatch_arp_reply(event, arp_payload, target_mac, src_port)
                    self._deploy_virtual_routing(client_ip, packet.src, target_ip, target_mac, src_port)
                else:
                    if arp_payload.protodst in self.address_table:
                        known_mac, _ = self.address_table[arp_payload.protodst]
                        self._dispatch_arp_reply(event, arp_payload, known_mac, src_port,
                                                 override_ip=arp_payload.protodst)
                    else:
                        self._broadcast(event)
            return

        elif packet.type == pkt.ethernet.IP_TYPE:
            ip_payload = packet.payload
            if ip_payload.dstip == self.virtual_gateway:
                client_ip = ip_payload.srcip
                if client_ip in self.client_allocation:
                    target_ip, target_mac = self.client_allocation[client_ip]
                    log.info("Forwarding from %s via allocated backend %s", client_ip, target_ip)
                else:
                    target_ip, target_mac = self._select_backend()
                    self.client_allocation[client_ip] = (target_ip, target_mac)
                    log.info("Assigning %s to backend %s", client_ip, target_ip)
                    self._deploy_virtual_routing(client_ip, packet.src, target_ip, target_mac, src_port)
                backend_port = 5 if str(target_ip) == "10.0.0.5" else 6
                msg = of.ofp_packet_out()
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_nw_addr.set_dst(target_ip))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(target_mac))
                msg.actions.append(of.ofp_action_output(port=backend_port))
                self.connection.send(msg)
                log.info("Packet from %s routed to backend %s", client_ip, target_ip)
            else:
                log.info("Packet not for virtual gateway, flooding")
                self._broadcast(event)
            return

        else:
            self._broadcast(event)

    def _refresh_address_table(self, packet, src_port):
        if packet.type == pkt.ethernet.ARP_TYPE:
            arp_payload = packet.payload
            if arp_payload.opcode in (pkt.arp.REQUEST, pkt.arp.REPLY):
                self.address_table[arp_payload.protosrc] = (arp_payload.hwsrc, src_port)
        elif packet.type == pkt.ethernet.IP_TYPE:
            ip_payload = packet.npayload
            self.address_table[ip_payload.srcip] = (packet.src, src_port)

    def _dispatch_arp_reply(self, event, arp_request, reply_mac, output_port, override_ip=None):
        response = pkt.arp()
        response.opcode = pkt.arp.REPLY
        response.hwdst = arp_request.hwsrc
        response.protodst = arp_request.protosrc
        response.protosrc = override_ip if override_ip else self.virtual_gateway
        response.hwsrc = reply_mac

        eth_frame = pkt.ethernet()
        eth_frame.type = pkt.ethernet.ARP_TYPE
        eth_frame.dst = arp_request.hwsrc
        eth_frame.src = reply_mac
        eth_frame.set_payload(response)

        msg = of.ofp_packet_out()
        msg.data = eth_frame.pack()
        msg.actions.append(of.ofp_action_output(port=output_port))
        self.connection.send(msg)
        log.info("Dispatched ARP reply for %s at %s to port %s", response.protosrc, reply_mac, output_port)

    def _deploy_virtual_routing(self, client_ip, client_mac, backend_ip, backend_mac, client_port):
        backend_port = 5 if str(backend_ip) == "10.0.0.5" else 6

        flow_to_backend = of.ofp_flow_mod()
        flow_to_backend.match.in_port = client_port
        flow_to_backend.match.dl_type = 0x0800
        flow_to_backend.match.nw_dst = self.virtual_gateway
        flow_to_backend.actions.append(of.ofp_action_nw_addr.set_dst(backend_ip))
        flow_to_backend.actions.append(of.ofp_action_dl_addr.set_dst(backend_mac))
        flow_to_backend.actions.append(of.ofp_action_output(port=backend_port))
        self.connection.send(flow_to_backend)
        log.info("Flow set: %s -> %s", client_ip, backend_ip)

        flow_to_client = of.ofp_flow_mod()
        flow_to_client.match.in_port = backend_port
        flow_to_client.match.dl_type = 0x0800
        flow_to_client.match.nw_src = backend_ip
        flow_to_client.match.nw_dst = client_ip
        flow_to_client.actions.append(of.ofp_action_nw_addr.set_src(self.virtual_gateway))
        flow_to_client.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(flow_to_client)
        log.info("Flow set: %s -> %s", backend_ip, client_ip)

    def _broadcast(self, event):
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch():
    def activate_switch(event):
        LoadBalancerController(event.connection)
    core.openflow.addListenerByName("ConnectionUp", activate_switch)
