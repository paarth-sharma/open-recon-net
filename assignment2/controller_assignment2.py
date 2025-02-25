from pox.core import core
import pox.lib.packet as pkt
import pox.lib.packet.ethernet as eth
import pox.lib.packet.arp as arp
import pox.lib.packet.icmp as icmp
import pox.lib.packet.ipv4 as ip
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr

log = core.getLogger()

# A table to map (switch_dpid, source_MAC) -> input_port for basic learning.
table = {}

# A list of firewall and QoS "rules." Each rule is a dictionary:
#  - EthSrc / EthDst: match these MACs
#  - (optional) TCPPort: match this TCP destination port
#  - queue: the queue ID to use if forwarding (for shaping)
#  - drop: if True, traffic is blocked
# 
# We handle the "shaped" flows by specifying a queue, while "uncapped"
# flows also have a queue=0 with a large max‐rate. 
# We also create catch‐all rules for the same pair to allow ARP/ICMP (no TCPPort).
rules = [
  # 1) H1->H3 on TCP port 40 => shaped at queue=0 (30Mb/s) 
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03','TCPPort':40,'queue':0,'drop':False},

  # 2) H1->H2 on TCP port 60 => shaped at queue=1 (150Mb/s)
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02','TCPPort':60,'queue':1,'drop':False},

  # 3) H1->H4 => uncapped
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:04','queue':0,'drop':False},

  # 4) H2->H4 => shaped at queue=1 (200Mb/s)
  {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:04','queue':1,'drop':False},
  # 4b) H2->H1 => uncapped
  {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},
  # 4c) H2->H3 => uncapped
  {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:03','queue':0,'drop':False},

  # 5) H3->H1 => uncapped
  {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},
  # 5b) H3->H2 => uncapped
  {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:02','queue':0,'drop':False},

  # 6) H4->H1 => uncapped
  {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},
  # 6b) H4->H2 => uncapped
  {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:02','queue':0,'drop':False},

  # Firewall rules: block all traffic between H3 and H4, in both directions:
  {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:04','drop':True},
  {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:03','drop':True},
]

def launch():
    """
    Called by POX upon module load. Registers our handlers for:
      - ConnectionUp (switch just connected)
      - PacketIn (incoming packet that didn't match a flow rule)
    """
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn",    _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp(event):
    """
    Fired when a switch connects. We clear any old flows on that switch
    to start with a clean slate.
    """
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    clear_flows = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(clear_flows)

def _handle_PacketIn(event):
    """
    This function is triggered whenever the switch has a packet
    that doesn't match any installed flow. We'll examine it, check
    our rules, and install new flow entries or drop as needed.
    """
    dpid       = event.connection.dpid   # numeric ID of the switch
    sw         = dpidToStr(dpid)         # string for logging
    inport     = event.port              # input port
    eth_packet = event.parsed            # the parsed Ethernet frame

    log.debug("PacketIn: switch %s port %s packet %s", sw, inport, eth_packet)

    # 1) Learn the input port for this source MAC, so we can route back later:
    table[(dpid, eth_packet.src)] = inport

    # 2) If we already know how to reach the destination MAC, we store the port:
    dst_port = table.get((dpid, eth_packet.dst))

    # 3) Special handling for ARP broadcast if destination is unknown:
    if (dst_port is None and
        eth_packet.type == eth.ARP_TYPE and
        eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff")):
        # This is an ARP broadcast => Flood it out all ports (except the input).
        pkt_out = of.ofp_packet_out()
        pkt_out.in_port = inport
        pkt_out.data    = event.ofp
        pkt_out.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(pkt_out)
        return  # done

    # 4) Check each rule in our "rules" list
    for rule in rules:
        if (eth_packet.src == EthAddr(rule['EthSrc']) and
            eth_packet.dst == EthAddr(rule['EthDst'])):

            # If the rule includes a TCPPort, verify this packet is actually TCP 
            # on that port:
            if 'TCPPort' in rule:
                if eth_packet.type != eth_packet.IP_TYPE:
                    # Not an IP packet => skip this rule
                    continue
                ip_pkt = eth_packet.find('ipv4')
                if not ip_pkt or ip_pkt.protocol != ip.TCP_PROTOCOL:
                    # Not a TCP packet => skip
                    continue
                tcp_pkt = eth_packet.find('tcp')
                if not tcp_pkt or tcp_pkt.dstport != rule['TCPPort']:
                    # Different TCP port => skip
                    continue

            # At this point, we have a match => install a flow entry
            fm = of.ofp_flow_mod()
            fm.soft_timeout = 40  # 40-second flow entry as required
            fm.match.dl_src = eth_packet.src
            fm.match.dl_dst = eth_packet.dst

            # If also matching a TCP port in the flow:
            if 'TCPPort' in rule:
                fm.match.dl_type = 0x800   # IPv4
                fm.match.nw_proto = 6      # TCP
                fm.match.tp_dst   = rule['TCPPort']

            # If the rule says drop, we do not add any actions => drop
            if rule['drop']:
                # no actions => drop
                pass
            else:
                # Otherwise we forward, possibly with a queue for rate-limiting
                if dst_port is not None:
                    if 'queue' in rule:
                        # Use ofp_action_enqueue to specify queue ID 
                        fm.actions.append(of.ofp_action_enqueue(
                            port=dst_port, queue_id=rule['queue'])
                        )
                    else:
                        # Normal forwarding with no queue shaping
                        fm.actions.append(of.ofp_action_output(port=dst_port))

            # Send the flow_mod to the switch
            event.connection.send(fm)

            # Also send out this *current* packet (so it is not dropped)
            po = of.ofp_packet_out()
            po.data    = event.ofp
            po.in_port = inport

            if not rule['drop'] and dst_port is not None:
                # Forward the current packet with the same logic
                if 'queue' in rule:
                    po.actions.append(of.ofp_action_enqueue(
                        port=dst_port, queue_id=rule['queue']))
                else:
                    po.actions.append(of.ofp_action_output(port=dst_port))

            event.connection.send(po)

            return  # Stop checking other rules, done

    # 5) If we reach here, no rule matched => default is to drop
    #    This also prevents unknown flows from flooding uncontrollably.
    fm = of.ofp_flow_mod()
    fm.soft_timeout = 40
    fm.match.dl_src = eth_packet.src
    fm.match.dl_dst = eth_packet.dst

    # If IP, also match that so subsequent packets are dropped 
    # without going to the controller again
    if eth_packet.type == eth_packet.IP_TYPE:
        fm.match.dl_type = 0x800
        ip_pkt = eth_packet.find('ipv4')
        if ip_pkt and ip_pkt.protocol == ip.TCP_PROTOCOL:
            tcp_pkt = eth_packet.find('tcp')
            if tcp_pkt:
                fm.match.nw_proto = 6      # TCP
                fm.match.tp_dst   = tcp_pkt.dstport

    event.connection.send(fm)

    # Drop the *current* packet_in:
    po = of.ofp_packet_out(data=event.ofp, in_port=inport)
    event.connection.send(po)
