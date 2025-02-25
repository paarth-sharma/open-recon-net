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

# We store (dpid, MAC) -> port
table = {}

# Here we define *two* rules for each shaped flow: one for the shaped port,
# one catch-all for “other traffic.” We also have drop rules for H3<->H4.
rules = [
  # 1) H1->H3 on TCP port 40 => shape at queue=0 (30Mb/s on s2-eth1),
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03','TCPPort':40,
   'queue':0,'drop':False},
  # 1b) H1->H3 catch-all => uncapped
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03',
   'queue':0,'drop':False},

  # 2) H1->H2 on TCP port 60 => shape at queue=1 (150Mb/s on s1-eth2)
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02','TCPPort':60,
   'queue':1,'drop':False},
  # 2b) H1->H2 catch-all => uncapped
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02',
   'queue':0,'drop':False},

  # 3) H1->H4 => uncapped
  {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:04','queue':0,'drop':False},

  # 4) H2->H4 => shape at queue=1 (200Mb/s on s2-eth2)
  {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:04','queue':1,'drop':False},
  # 4b) Also allow H2->H1 => uncapped
  {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},
  # 4c) Also allow H2->H3 => uncapped
  {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:03','queue':0,'drop':False},

  # 5) H3->H1 => uncapped
  {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},
  # 5b) H3->H2 => uncapped
  {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:02','queue':0,'drop':False},

  # 6) H4->H1 => uncapped
  {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:01','queue':0,'drop':False},
  # 6b) H4->H2 => uncapped
  {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:02','queue':0,'drop':False},
  # 6c) H4->H3 => blocked
  #    (But we’ll do that with the firewall lines below)

  # Firewall rules: block H3 <-> H4
  {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:04','drop':True},
  {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:03','drop':True},
]

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp(event):
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    # Clear old flows on switch
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    event.connection.send(msg)

def _handle_PacketIn(event):
    dpid       = event.connection.dpid
    sw         = dpidToStr(dpid)
    inport     = event.port
    eth_packet = event.parsed

    log.debug("Event: switch %s port %s packet %s", sw, inport, eth_packet)

    # Learn the source MAC -> inport
    table[(dpid, eth_packet.src)] = inport
    dst_port = table.get((dpid, eth_packet.dst))

    # 1) Handle ARP broadcast if we don't know the destination
    if (dst_port is None and
        eth_packet.type == eth.ARP_TYPE and
        eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff")):
        # Flood ARP request
        pkt_out = of.ofp_packet_out()
        pkt_out.in_port = inport
        pkt_out.data = event.ofp
        pkt_out.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(pkt_out)
        return

    # 2) Check each firewall/QoS rule
    for rule in rules:
        if (eth_packet.src == EthAddr(rule['EthSrc']) and
            eth_packet.dst == EthAddr(rule['EthDst'])):

            # If rule has 'TCPPort', verify packet is IPv4/TCP and matches that port
            if 'TCPPort' in rule:
                if eth_packet.type != eth_packet.IP_TYPE:
                    continue
                ip_pkt = eth_packet.find('ipv4')
                if not ip_pkt or ip_pkt.protocol != ip.TCP_PROTOCOL:
                    continue
                tcp_pkt = eth_packet.find('tcp')
                if not tcp_pkt or tcp_pkt.dstport != rule['TCPPort']:
                    continue

            # We have a match => install a flow
            fm = of.ofp_flow_mod()
            fm.soft_timeout = 40
            fm.match.dl_src = eth_packet.src
            fm.match.dl_dst = eth_packet.dst
            # If also matching TCP port
            if 'TCPPort' in rule:
                fm.match.dl_type = 0x800  # IPv4
                fm.match.nw_proto = 6     # TCP
                fm.match.tp_dst   = rule['TCPPort']

            if rule['drop']:
                # drop => no actions
                pass
            else:
                # otherwise forward out known port if we have it
                if dst_port is not None:
                    if 'queue' in rule:
                        fm.actions.append(of.ofp_action_enqueue(port=dst_port,
                                                               queue_id=rule['queue']))
                    else:
                        fm.actions.append(of.ofp_action_output(port=dst_port))

            # Send the flow_mod
            event.connection.send(fm)

            # Also send the current packet
            po = of.ofp_packet_out()
            po.data = event.ofp
            po.in_port = inport
            if not rule['drop'] and dst_port is not None:
                if 'queue' in rule:
                    po.actions.append(of.ofp_action_enqueue(port=dst_port,
                                                           queue_id=rule['queue']))
                else:
                    po.actions.append(of.ofp_action_output(port=dst_port))
            event.connection.send(po)

            return  # done

    # 3) If no rule matched => drop
    fm = of.ofp_flow_mod()
    fm.soft_timeout = 40
    fm.match.dl_src = eth_packet.src
    fm.match.dl_dst = eth_packet.dst

    # If IP, match that so future identical flows get dropped
    if eth_packet.type == eth_packet.IP_TYPE:
        fm.match.dl_type = 0x800
        ip_pkt = eth_packet.find('ipv4')
        if ip_pkt and ip_pkt.protocol == ip.TCP_PROTOCOL:
            tcp_pkt = eth_packet.find('tcp')
            if tcp_pkt:
                fm.match.nw_proto = 6
                fm.match.tp_dst   = tcp_pkt.dstport

    event.connection.send(fm)
    # Also drop the current packet
    po = of.ofp_packet_out(data=event.ofp, in_port=inport)
    event.connection.send(po)
