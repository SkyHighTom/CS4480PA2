# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

# Create a logger for this component
log = core.getLogger()
getMac = {IPAddr("10.0.0.1") : EthAddr("00:00:00:00:00:01"),
          IPAddr("10.0.0.2") : EthAddr("00:00:00:00:00:02"),
          IPAddr("10.0.0.3") : EthAddr("00:00:00:00:00:03"),
          IPAddr("10.0.0.4") : EthAddr("00:00:00:00:00:04"),
          IPAddr("10.0.0.5") : EthAddr("00:00:00:00:00:05"),
          IPAddr("10.0.0.6") : EthAddr("00:00:00:00:00:06")}
getIPFromMac = {EthAddr("00:00:00:00:00:01") : IPAddr("10.0.0.1"),
                EthAddr("00:00:00:00:00:02") : IPAddr("10.0.0.2"),
                EthAddr("00:00:00:00:00:03") : IPAddr("10.0.0.3"),
                EthAddr("00:00:00:00:00:04") : IPAddr("10.0.0.4"),
                EthAddr("00:00:00:00:00:05") : IPAddr("10.0.0.5"),
                EthAddr("00:00:00:00:00:06") : IPAddr("10.0.0.6")}
client_ips = [IPAddr(f"10.0.0.{i}") for i in range(1,5)]
server_ips = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]
current_server = 0
round_robin = {IPAddr("10.0.0.5") : IPAddr("10.0.0.5"),
               IPAddr("10.0.0.6") : IPAddr("10.0.0.6")}


def _go_up (event):
  log.info("Application up")

def install_flow_rule(event, port1, port2, client_ip, backend_ip, virtual_ip):
    """
    Adds bidirectional flow rules:
    - client -> virtual_ip -> backend
    - backend -> client (src_ip rewritten to virtual_ip)
    """
    log.info(f"Installing flow rule: {port1} <-> {port2}")

    # Flow rule: Client to Backend
    msg1 = of.ofp_flow_mod()
    msg1.match.in_port = port1
    msg1.match.dl_type = pkt.ethernet.IP_TYPE  # Match only IP packets
    msg1.match.nw_dst = virtual_ip  # Match the virtual service IP (10.0.0.10)
    msg1.actions.append(of.ofp_action_nw_addr.set_dst(backend_ip))  # Rewrite dst IP
    msg1.actions.append(of.ofp_action_dl_addr.set_dst(getMac[backend_ip]))  # Set MAC
    msg1.actions.append(of.ofp_action_output(port=port2))  # Forward to backend
    event.connection.send(msg1)

    # Flow rule: Backend to Client (Rewrite src IP)
    msg2 = of.ofp_flow_mod()
    msg2.match.in_port = port2
    msg2.match.dl_type = pkt.ethernet.IP_TYPE  # Match only IP packets
    msg2.match.nw_src = backend_ip  # Match backend server IP
    msg2.match.nw_dst = client_ip  # Match original client IP
    msg2.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))  # Rewrite src IP to 10.0.0.10
    msg2.actions.append(of.ofp_action_output(port=port1))  # Send back to client
    event.connection.send(msg2)

def _handle_PacketIn(event):
    global current_server
    packet = event.parsed
    log.info("PacketIn event received")

    if packet.type == pkt.ethernet.ARP_TYPE:
        arp_packet = packet.payload
        if arp_packet.protodst == IPAddr("10.0.0.10"):  # Virtual service IP
            backend_ip = server_ips[current_server % len(server_ips)]
            current_server += 1

            log.info(f"Handling ARP request for virtual IP 10.0.0.10, mapping to {backend_ip}")

            # Send ARP reply pretending to be 10.0.0.10
            arp_reply = pkt.arp()
            arp_reply.hwsrc = getMac[backend_ip]  # Use backend MAC
            arp_reply.hwdst = packet.src
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.protosrc = IPAddr("10.0.0.10")  # Set source as virtual IP
            arp_reply.protodst = arp_packet.protosrc

            ether = pkt.ethernet()
            ether.type = pkt.ethernet.ARP_TYPE  
            ether.dst = packet.src
            ether.src = getMac[backend_ip]  # Use backend MAC
            ether.payload = arp_reply

            packet_out = of.ofp_packet_out()
            packet_out.data = ether.pack()
            packet_out.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(packet_out)

    elif packet.type == pkt.ethernet.IP_TYPE:
        ip_packet = packet.payload
        if ip_packet.dstip == IPAddr("10.0.0.10"):
            backend_ip = server_ips[current_server % len(server_ips)]
            current_server += 1
            client_ip = ip_packet.srcip

            client_port = int(str(client_ip)[-1])
            backend_port = int(str(backend_ip)[-1])

            install_flow_rule(event, client_port, backend_port, client_ip, backend_ip, IPAddr("10.0.0.10"))



@poxutil.eval_args
def launch ():
  core.addListenerByName("UpEvent", _go_up)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
