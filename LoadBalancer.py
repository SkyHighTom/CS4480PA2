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

def install_flow_rule(event, port1, port2):
    # Flow: Packets from port1 go to port2
    log.info("port1: " + str(port1) + ", port2: " + str(port2))
    msg1 = of.ofp_flow_mod()
    msg1.match.in_port = port1
    msg1.actions.append(of.ofp_action_output(port=port2))
    event.connection.send(msg1)

    # Flow: Packets from port2 go to port1
    msg2 = of.ofp_flow_mod()
    msg2.match.in_port = port2
    msg2.actions.append(of.ofp_action_output(port=port1))
    event.connection.send(msg2)

def _handle_PacketIn(event):
    log.info("packetin")
    global current_server
    packet = event.parsed
    if packet.type == packet.ARP_TYPE:
        arp_packet = packet.payload
        if arp_packet.protodst not in round_robin:
            round_robin[arp_packet.protodst] = server_ips[current_server%len(server_ips)]
            current_server += 1
        dest = round_robin[arp_packet.protodst]
        if packet.payload.opcode == pkt.arp.REQUEST:
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
            #send this packet to the switch
            packet_out = of.ofp_packet_out()
            packet_out.data = ether.pack()  # Pack Ethernet frame
            packet_out.actions.append(of.ofp_action_output(port=event.port))  # Send it back to the source port
            event.connection.send(packet_out)

            client_port = int(str(arp_packet.protosrc)[-1])
            server_port = int(str(dest)[-1])
            install_flow_rule(event, client_port, server_port)

    elif packet.type == packet.IP_TYPE:
        ip_packet = packet.payload
        if ip_packet.dstip not in round_robin:
            round_robin[ip_packet.dstip] = server_ips[current_server % len(server_ips)]
            current_server += 1

        backend_ip = round_robin[ip_packet.dstip]

        client_port = int(str(ip_packet.srcip)[-1])
        server_port = int(str(backend_ip)[-1])
        install_flow_rule(event, client_port, server_port)

        # Step 2: Modify IP packet destination
        ip_packet.dstip = backend_ip

        # Step 3: Modify Ethernet Frame
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.IP_TYPE
        ether.src = getMac[ip_packet.srcip]  # Source MAC remains unchanged
        ether.dst = getMac[backend_ip]  # Destination MAC for backend server
        ether.payload = ip_packet

        # Step 4: Forward the packet
        packet_out = of.ofp_packet_out()
        packet_out.data = ether.pack()  # Pack Ethernet frame
        packet_out.actions.append(of.ofp_action_output(port=event.port))  # Send it back to the source port
        event.connection.send(packet_out)


@poxutil.eval_args
def launch ():
  core.addListenerByName("UpEvent", _go_up)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
