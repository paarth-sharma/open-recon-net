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

table={}

rules=[
    # QoS Rules
    {'EthSrc':'00:00:00:00:00:01', 'EthDst':'00:00:00:00:00:03', 'TCPPort':40, 'queue':0, 'drop':False},  # H1->H3: 30Mbps
    {'EthSrc':'00:00:00:00:00:01', 'EthDst':'00:00:00:00:00:02', 'TCPPort':60, 'queue':1, 'drop':False},  # H1->H2: 150Mbps

    # H1->H4: uncapped => use queue=0 (very high max rate)
    {'EthSrc':'00:00:00:00:00:01', 'EthDst':'00:00:00:00:00:04', 'queue':0, 'drop':False},

    # H2->H1: uncapped => queue=0
    {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},

    # H2->H4: 200Mbps => queue=0 on s2-eth2
    {'EthSrc':'00:00:00:00:00:02', 'EthDst':'00:00:00:00:00:04', 'queue':0, 'drop':False},

    # H2->H3: uncapped => queue=0
    {'EthSrc':'00:00:00:00:00:02', 'EthDst':'00:00:00:00:00:03', 'queue':0, 'drop':False},

    # H3->H1: uncapped => queue=0
    {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},
    # (duplicate kept per the template)
    {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},

    # H4->H1: uncapped => queue=0
    {'EthSrc':'00:00:00:00:00:04', 'EthDst':'00:00:00:00:00:01', 'queue':0, 'drop':False},

    # H4->H2: uncapped => queue=0
    {'EthSrc':'00:00:00:00:00:04', 'EthDst':'00:00:00:00:00:02', 'queue':0, 'drop':False},

    # Firewall Rules - block H3 <--> H4
    {'EthSrc':'00:00:00:00:00:03', 'EthDst':'00:00:00:00:00:04', 'drop':True},
    {'EthSrc':'00:00:00:00:00:04', 'EthDst':'00:00:00:00:00:03', 'drop':True}
]


def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn",  _handle_PacketIn)
    log.info("Switch running.")


def _handle_ConnectionUp ( event):
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    # Remove any old flows
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(msg)


def _handle_PacketIn ( event):
    dpid = event.connection.dpid
    sw = dpidToStr(dpid)
    inport = event.port
    eth_packet = event.parsed

    log.debug("Event: switch %s port %s packet %s" % (sw, inport, eth_packet))

    # Record which port we saw this SRC MAC on
    table[(dpid, eth_packet.src)] = inport
    dst_port = table.get((dpid, eth_packet.dst))

    ######################################################################################
    ############ CODE SHOULD ONLY BE ADDED BELOW  #################################

    # ARP broadcast helper
    if dst_port is None and eth_packet.type == eth.ARP_TYPE and \
       eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff"):
        # Flood ARP request so that hosts learn each other’s MAC
        pkt_out = of.ofp_packet_out()
        pkt_out.in_port = inport
        pkt_out.data    = event.ofp
        pkt_out.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(pkt_out)
        return

    # Go through each rule in the dictionary
    for rule in rules:
        if (eth_packet.dst == EthAddr(rule['EthDst']) and eth_packet.src == EthAddr(rule['EthSrc'])):
            log.debug("Event: found rule from %s -> %s" % (eth_packet.src, eth_packet.dst))

            # If the rule has a TCPPort, ensure packet is TCP on that port
            if 'TCPPort' in rule:
                if eth_packet.type != eth_packet.IP_TYPE:
                    continue
                ip_packet = eth_packet.find('ipv4')
                if not ip_packet or ip_packet.protocol != ip.TCP_PROTOCOL:
                    continue
                tcp_packet = eth_packet.find('tcp')
                if not tcp_packet or tcp_packet.dstport != rule['TCPPort']:
                    continue

            # Prepare a flow_mod with 40s soft_timeout
            fm = of.ofp_flow_mod()
            fm.soft_timeout = 40
            fm.match.dl_src = eth_packet.src
            fm.match.dl_dst = eth_packet.dst

            # If we matched a specific TCP port, add IP/TCP match fields
            if 'TCPPort' in rule:
                fm.match.dl_type = 0x800  # IPv4
                fm.match.nw_proto = 6    # TCP
                fm.match.tp_dst   = rule['TCPPort']

            # If this rule is drop=True, install a drop flow
            if rule['drop']:
                # no actions
                pass
            else:
                # If we found a known out port, enqueue or normal output
                if dst_port is not None:
                    if 'queue' in rule:
                        fm.actions.append(of.ofp_action_enqueue(port = dst_port,
                                                                queue_id = rule['queue']))
                    else:
                        fm.actions.append(of.ofp_action_output(port = dst_port))

            # Send the flow_mod to the switch
            event.connection.send(fm)

            # Also send this current packet out (packet_out)
            po = of.ofp_packet_out()
            po.data    = event.ofp
            po.in_port = inport
            if not rule['drop'] and dst_port is not None:
                if 'queue' in rule:
                    po.actions.append(of.ofp_action_enqueue(port = dst_port,
                                                            queue_id = rule['queue']))
                else:
                    po.actions.append(of.ofp_action_output(port = dst_port))
            event.connection.send(po)

            # Done handling this packet
            return

    # If we reach here, no rule matched => install a drop
    fm = of.ofp_flow_mod()
    fm.soft_timeout = 40
    fm.match.dl_src = eth_packet.src
    fm.match.dl_dst = eth_packet.dst

    # If it’s IP/TCP, match those fields so that future identical flows also get dropped
    if eth_packet.type == eth_packet.IP_TYPE:
        fm.match.dl_type = 0x800
        ip_packet = eth_packet.find('ipv4')
        if ip_packet and ip_packet.protocol == ip.TCP_PROTOCOL:
            fm.match.nw_proto = 6
            tcp_packet = eth_packet.find('tcp')
            if tcp_packet:
                fm.match.tp_dst = tcp_packet.dstport

    # No actions => drop rule
    event.connection.send(fm)

    # Also drop the *current* packet
    po = of.ofp_packet_out(data=event.ofp, in_port=inport)
    event.connection.send(po)
