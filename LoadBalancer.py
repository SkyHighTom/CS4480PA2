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
    def __init__(self, datapath, arp_table, round_robin):
        self.datapath = datapath
        self.arp_table = arp_table  # Improved ARP table handling
        self.round_robin = round_robin  # Retained round-robin approach for multiple VIPs
        self.flow_rules_installed = set()

    def handle_packet_in(self, msg):
        if self.is_arp_request(msg):
            self.process_arp_request(msg)
        elif self.is_tcp_packet(msg):
            self.process_tcp_packet(msg)

    def process_arp_request(self, msg):
        vip = self.extract_virtual_ip(msg)
        if vip in self.arp_table:
            self.reply_arp(msg, self.arp_table[vip])
        else:
            self.forward_arp_request(msg)

    def process_tcp_packet(self, msg):
        vip = self.extract_virtual_ip(msg)
        if vip in self.round_robin:
            backend_ip = self.get_next_backend(vip)
            self.install_bidirectional_flow_rules(msg, backend_ip)
            self.forward_tcp_packet(msg, backend_ip)

    def install_bidirectional_flow_rules(self, msg, backend_ip):
        client_ip = self.extract_client_ip(msg)
        if (client_ip, backend_ip) not in self.flow_rules_installed:
            self.add_flow_rule(msg, client_ip, backend_ip, direction="client_to_server")
            self.add_flow_rule(msg, backend_ip, client_ip, direction="server_to_client")
            self.flow_rules_installed.add((client_ip, backend_ip))

    def add_flow_rule(self, msg, src_ip, dst_ip, direction):
        flow_mod = self.create_flow_mod(msg, src_ip, dst_ip, direction)
        self.datapath.send(flow_mod)

    def get_next_backend(self, vip):
        backend_list = self.round_robin[vip]
        backend = backend_list.pop(0)
        backend_list.append(backend)  # Rotate backend selection
        return backend

    def create_flow_mod(self, msg, src_ip, dst_ip, direction):
        flow_mod = of.ofp_flow_mod()
        flow_mod.match.dl_type = pkt.ethernet.IP_TYPE
        flow_mod.match.nw_src = src_ip
        flow_mod.match.nw_dst = dst_ip
        if direction == "client_to_server":
            flow_mod.actions.append(of.ofp_action_nw_addr.set_dst(dst_ip))
        else:
            flow_mod.actions.append(of.ofp_action_nw_addr.set_src(src_ip))
        return flow_mod

@poxutil.eval_args
def launch():
    def _go_up(event):
        log.info("Connection up")
        LoadBalancerController(event.connection)
    core.addListenerByName("ConnectionUp", _go_up)
