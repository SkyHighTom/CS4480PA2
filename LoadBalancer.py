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

# Static MAC and IP mappings
getMac = {IPAddr(f"10.0.0.{i}"): EthAddr(f"00:00:00:00:00:0{i}") for i in range(1, 7)}
getIPFromMac = {v: k for k, v in getMac.items()}

# Client and server IPs
client_ips = [IPAddr(f"10.0.0.{i}") for i in range(1, 5)]
server_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
current_server = 0
round_robin = {IPAddr("10.0.0.5"): IPAddr("10.0.0.5"),
               IPAddr("10.0.0.6"): IPAddr("10.0.0.6")}

def _go_up(event):
    log.info("Application up")

def install_flow_rule(packet_type, client_port, server_port, dest_ip, connection):
    """Installs bidirectional flow rules between a client and server."""
    log.info(f"Installing flow rule: {client_port} <-> {server_port}")
    
    # Client to Server
    msg1 = of.ofp_flow_mod()
    msg1.match.in_port = client_port
    msg1.match.dl_type = packet_type
    msg1.match.nw_dst = dest_ip
    msg1.actions.append(of.ofp_action_dl_addr.set_src(getMac[IPAddr(f"10.0.0.{client_port}")]))
    msg1.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(f"10.0.0.{client_port}")))
    msg1.actions.append(of.ofp_action_dl_addr.set_dst(getMac[IPAddr(f"10.0.0.{server_port}")]))
    msg1.actions.append(of.ofp_action_nw_addr.set_dst(dest_ip))
    msg1.actions.append(of.ofp_action_output(port=server_port))

    connection.send(msg1)  # <-- Send the flow mod message to the switch!

    # Server to Client
    msg2 = of.ofp_flow_mod()
    msg2.match.in_port = server_port
    msg2.match.dl_type = packet_type
    msg2.match.nw_dst = IPAddr(f"10.0.0.{client_port}")
    msg2.match.nw_src = IPAddr(f"10.0.0.{server_port}")
    msg2.actions.append(of.ofp_action_dl_addr.set_src(getMac[IPAddr(f"10.0.0.{server_port}")]))
    msg1.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(f"10.0.0.{server_port}")))
    msg1.actions.append(of.ofp_action_dl_addr.set_dst(getMac[IPAddr(f"10.0.0.{client_port}")]))
    msg2.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(f"10.0.0.{client_port}")))
    msg2.actions.append(of.ofp_action_output(port=client_port))

    connection.send(msg2)  # <-- Send the rule

def _handle_PacketIn(event):
    global current_server
    packet = event.parsed
    connection = event.connection  # Get the switch connection
    if getIPFromMac[packet.src] in server_ips:
        return
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return
    log.info("PacketIn event")
    
    if packet.type == packet.ARP_TYPE:
        arp_packet = packet.payload
        actual_ip = arp_packet.protodst
        log.info("ARP " + str(actual_ip))
        if arp_packet.protodst not in round_robin:
            round_robin[arp_packet.protodst] = server_ips[current_server % len(server_ips)]
            current_server += 1
        dest = round_robin[arp_packet.protodst]
        
        if arp_packet.opcode == pkt.arp.REQUEST:
            arp_reply = pkt.arp()
            mac = getMac[dest]
            arp_reply.hwsrc = mac
            arp_reply.hwdst = packet.src
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.protosrc = getIPFromMac[mac]
            arp_reply.protodst = arp_packet.protosrc
            ether = pkt.ethernet()
            ether.type = pkt.ethernet.ARP_TYPE  
            ether.dst = packet.src
            ether.src = mac
            ether.payload = arp_reply
            
            packet_out = of.ofp_packet_out()
            packet_out.data = ether.pack()
            packet_out.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(packet_out)
            
            client_port = int(str(arp_packet.protosrc)[-1])
            server_port = int(str(dest)[-1])
            install_flow_rule(pkt.ethernet.ARP_TYPE, client_port, server_port, actual_ip, connection)
    
    elif packet.type == packet.IP_TYPE:
        ip_packet = packet.payload
        actual_ip = ip_packet.dstip
        log.info("IP " + str(actual_ip))
        if ip_packet.dstip not in round_robin:
            round_robin[ip_packet.dstip] = server_ips[current_server % len(server_ips)]
            current_server += 1
        
        backend_ip = round_robin[ip_packet.dstip]
        client_port = int(str(ip_packet.srcip)[-1])
        server_port = int(str(backend_ip)[-1])
        
        install_flow_rule(pkt.ethernet.IP_TYPE, client_port, server_port, actual_ip, connection)
        
        # Modify the packet for load balancing
        ip_packet.dstip = backend_ip
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.IP_TYPE
        ether.src = getMac[ip_packet.srcip]
        ether.dst = getMac[backend_ip]
        ether.payload = ip_packet
        
        packet_out = of.ofp_packet_out()
        packet_out.data = ether.pack()
        packet_out.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(packet_out)

@poxutil.eval_args
def launch():
    core.addListenerByName("UpEvent", _go_up)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
