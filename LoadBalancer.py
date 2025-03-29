from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

class LoadBalancerController(object):
    def __init__(self, connection):
        self.connection = connection
        self.virtual_ip = IPAddr("10.0.0.10")
        # Static MAC and IP mappings
        self.getMac = {IPAddr(f"10.0.0.{i}"): EthAddr(f"00:00:00:00:00:0{i}") for i in range(1, 7)}
        self.getIPFromMac = {v: k for k, v in self.getMac.items()}

        # Client and server IPs
        self.client_ips = [IPAddr(f"10.0.0.{i}") for i in range(1, 5)]
        self.server_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]

        self.round_robin = {}
        self.current_server = 0
        self.arp_tbl = {}
        connection.addListeners(self)
        log.info("Connected")

    def _pick_round_robin(self):
        server_ip = self.server_ips[self.current_server]
        self.current_server = (self.current_server + 1) % len(self.server_ips)
        return server_ip

    def _handle_PacketIn(self, event):
        log.info("PacketIn")
        packet = event.parsed
        if not packet:
            return
        inport = event.port
        self._update_arp(packet, inport)

        if packet.type == packet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode == pkt.arp.REQUEST:
                if arp_pkt.protodst == self.virtual_ip:
                    client_ip = arp_pkt.protosrc
                    if client_ip in self.round_robin:
                        server_ip, server_mac = self.round_robin[client_ip]
                    else:
                        server_ip = self._pick_round_robin()
                        server_mac = self.getMac[server_ip]
                        self.round_robin[client_ip] = server_ip
                        log.info("Assigning client to server")
                    self._send_arp(event, arp_pkt, server_mac, inport)
                    self._install_virt_flow(client_ip, packet.src, server_ip, server_mac, inport)
                else:
                    if arp_pkt.protodst in self.arp_tbl:
                        dst_mac, _ = self.arp_tbl[arp_pkt.protodst]
                        self._send_arp(event, arp_pkt, dst_mac, inport,
                                             override_ip=arp_pkt.protodst)
                    else:
                        self._flood(event)
            return

        elif packet.type == packet.IP_TYPE:
            ip_packet = packet.next
            if ip_packet.dstip == self.virtual_ip:
                client_ip = ip_packet.srcip
                if client_ip in self.round_robin:
                    server_ip = self.round_robin[client_ip]
                    server_mac = self.getMac[server_ip]
                    log.info("IP from client assigned server")
                else:
                    server_ip = self._pick_round_robin()
                    server_mac = self.getMac[server_ip]
                    self.round_robin[client_ip] = server_ip
                    log.info("IP assigning client server")
                    self._install_virt_flow(client_ip, packet.src, server_ip, server_mac, inport)

                server_port = int(str(server_ip)[-1])
                msg = of.ofp_packet_out()
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                msg.actions.append(of.ofp_action_output(port=server_port))
                self.connection.send(msg)
                log.info("IP packet redirected")
            elif ip_packet.dstip in self.server_ips:
                client_ip = ip_packet.srcip
                server_ip = ip_packet.dstip
                server_mac = self.getMac[server_ip]
                if client_ip not in self.round_robin:
                    self.round_robin[client_ip] = server_ip
                    log.info("IP direct client assigned server")
                    self._install_virt_flow(client_ip, packet.src, server_ip, server_mac, inport)
                self._install_flow(client_ip, packet.src, server_ip, server_mac, inport)
                server_port = int(str(server_ip)[-1])
                msg = of.ofp_packet_out()
                msg.data = event.ofp.data
                msg.actions.append(of.ofp_action_output(port=server_port))
                self.connection.send(msg)
                log.info("IP direct redirect client server")
            else:
                log.info("IP not virt or server flood")
                self._flood(event)
            return

        else:
            self._flood(event)

    def _update_arp(self, packet, inport):
        if packet.type == pkt.ethernet.ARP_TYPE:
            arp_pkt = packet.next
            if arp_pkt.opcode in (pkt.arp.REQUEST, pkt.arp.REPLY):
                self.arp_tbl[arp_pkt.protosrc] = (arp_pkt.hwsrc, inport)
        elif packet.type == pkt.ethernet.IP_TYPE:
            ip_pkt = packet.next
            self.arp_tbl[ip_pkt.srcip] = (packet.src, inport)

    def _send_arp(self, event, arp_req, reply_mac, outport, override_ip=None):
        arp_reply = pkt.arp()
        arp_reply.opcode = pkt.arp.REPLY
        arp_reply.hwdst = arp_req.hwsrc
        arp_reply.protodst = arp_req.protosrc
        arp_reply.protosrc = override_ip if override_ip else self.virtual_ip
        arp_reply.hwsrc = reply_mac

        ether = pkt.ethernet()
        ether.type = pkt.ethernet.ARP_TYPE
        ether.dst = arp_req.hwsrc
        ether.src = reply_mac
        ether.set_payload(arp_reply)

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=outport))
        self.connection.send(msg)
        log.info("ARP Reply")

    def _install_virt_flow(self, client_ip, client_mac, server_ip, server_mac, client_port):
        server_port = int(str(server_ip)[-1])

        msgc = of.ofp_flow_mod()
        msgc.match.in_port = client_port
        msgc.match.dl_type = 0x0800
        msgc.match.nw_dst = self.virtual_ip
        msgc.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msgc.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msgc.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(msgc)
        log.info("Virt flow c-s")

        msgs = of.ofp_flow_mod()
        msgs.match.in_port = server_port
        msgs.match.dl_type = 0x0800
        msgs.match.nw_src = server_ip
        msgs.match.nw_dst = client_ip
        msgs.actions.append(of.ofp_action_nw_addr.set_src(self.virtual_ip))
        msgs.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msgs)
        log.info("Virt flow s-c")

    def _install_flow(self, client_ip, client_mac, server_ip, server_mac, client_port):
        server_port = int(str(server_ip)[-1])

        msgc = of.ofp_flow_mod()
        msgc.match.in_port = client_port
        msgc.match.dl_type = 0x0800
        msgc.match.nw_dst = server_ip
        msgc.actions.append(of.ofp_action_output(port=server_port))
        self.connection.send(msgc)
        log.info("flow c-s")

        msgs = of.ofp_flow_mod()
        msgs.match.in_port = server_port
        msgs.match.dl_type = 0x0800
        msgs.match.nw_src = server_ip
        msgs.match.nw_dst = client_ip
        msgs.actions.append(of.ofp_action_output(port=client_port))
        self.connection.send(msgs)
        log.info("flow s-c")

    def _flood(self, event):
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch():
    def _go_up(event):
        LoadBalancerController(event.connection)
    core.openflow.addListenerByName("ConnectionUp", _go_up)
