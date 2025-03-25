from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet, arp

# Configuration
VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [(IPAddr("10.0.0.5"), 5), (IPAddr("10.0.0.6"), 6)]  # (IP, port)
CLIENT_IPS = [IPAddr(f"10.0.0.{i}") for i in range(1, 5)]  # h1-h4
current_server = 0  # Round-robin counter

# Logger for debugging
log = core.getLogger()

def ip_to_mac(ip):
    """Convert IP (e.g., 10.0.0.5) to MAC (00:00:00:00:00:05)."""
    try:
        mac = EthAddr("00:00:00:00:00:%02x" % int(str(ip).split('.')[-1]))
        log.debug(f"Converted IP {ip} to MAC {mac}")
        return mac
    except Exception as e:
        log.error(f"Error converting IP {ip} to MAC: {e}")
        return None

def next_server():
    """Cycle through servers in round-robin."""
    global current_server
    server = SERVERS[current_server]
    current_server = (current_server + 1) % len(SERVERS)
    return server  # Returns (IP, port)

def send_arp_reply(mac, event, target_ip):
    """Send ARP reply with specified MAC."""
    log.debug(f"Sending ARP reply: MAC={mac}, Target IP={target_ip}, In Port={event.port}")
    
    arp_reply = arp(
        hwsrc=mac,
        hwdst=event.parsed.src,
        opcode=arp.REPLY,
        protosrc=target_ip,
        protodst=event.parsed.payload.protosrc
    )
    eth = ethernet(
        src=mac,
        dst=event.parsed.src,
        type=ethernet.ARP_TYPE
    )
    eth.payload = arp_reply
    msg = of.ofp_packet_out(
        data=eth.pack(),
        actions=[of.ofp_action_output(port=of.OFPP_IN_PORT)],
        in_port=event.port
    )
    event.connection.send(msg)

def install_openflow_rules(client_port, server_ip, server_port, client_ip, event):
    """Install rules for client-server communication."""
    try:
        # Client to Server: Rewrite dst IP to server IP
        match = of.ofp_match(
            in_port=client_port,
            dl_type=ethernet.IP_TYPE,
            nw_dst=VIRTUAL_IP
        )
        actions = [
            of.ofp_action_nw_dst(server_ip),
            of.ofp_action_output(port=server_port)
        ]
        event.connection.send(of.ofp_flow_mod(match=match, actions=actions))
        log.debug(f"Installed flow rule: Client to Server (IP={VIRTUAL_IP} -> {server_ip})")

        # Server to Client: Rewrite src IP to virtual IP
        match = of.ofp_match(
            in_port=server_port,
            dl_type=ethernet.IP_TYPE,
            nw_src=server_ip,
            nw_dst=client_ip
        )
        actions = [
            of.ofp_action_nw_src(VIRTUAL_IP),
            of.ofp_action_output(port=client_port)
        ]
        event.connection.send(of.ofp_flow_mod(match=match, actions=actions))
        log.debug(f"Installed flow rule: Server to Client (IP={server_ip} -> {VIRTUAL_IP})")
    
    except Exception as e:
        log.error(f"Error installing flow rules: {e}")

def handle_packet_in(event):
    """Handle ARP requests."""
    packet = event.parsed
    if packet.type != ethernet.ARP_TYPE:
        log.debug("Non-ARP packet received, ignoring.")
        return
    arp_pkt = packet.payload
    if arp_pkt.opcode != arp.REQUEST:
        log.debug("Received ARP reply, ignoring.")
        return

    target_ip = arp_pkt.protodst
    client_ip = arp_pkt.protosrc
    log.debug(f"Received ARP request: Target IP={target_ip}, Client IP={client_ip}")

    if target_ip == VIRTUAL_IP:
        # Virtual IP request: Assign server
        server_ip, server_port = next_server()
        server_mac = ip_to_mac(server_ip)
        if server_mac:
            send_arp_reply(server_mac, event, server_ip)
            install_openflow_rules(
                event.port, server_ip, server_port, client_ip, event
            )
        else:
            log.error(f"Failed to convert IP {server_ip} to MAC, skipping ARP reply.")
    elif target_ip in CLIENT_IPS:
        # Server querying client MAC
        client_mac = ip_to_mac(target_ip)
        if client_mac:
            send_arp_reply(client_mac, event, target_ip)
        else:
            log.error(f"Failed to convert IP {target_ip} to MAC, skipping ARP reply.")
    else:
        log.debug(f"ARP request not for virtual IP or known clients: {target_ip}")

def launch():
    core.openflow.addListenerByName("PacketIn", handle_packet_in)
    log.info("POX controller started and listening for packets.")
