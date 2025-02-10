from pox.core import core
import pox.lib.packet as pkt
import pox.lib.packet.ethernet as eth
import pox.lib.packet.arp as arp
import pox.lib.packet.ipv4 as ip
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr

log = core.getLogger()

table={}

rules=[
    {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03', 'TCPPort':40, 'queue':0, 'drop':False},
    {'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02', 'TCPPort':60, 'queue':1, 'drop':False},
    {'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:04', 'TCPPort':None, 'queue':2, 'drop':False},
    {'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:04', 'TCPPort':None, 'queue':None, 'drop':True},
    {'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:03', 'TCPPort':None, 'queue':None, 'drop':True}
]

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn",  _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp(event):
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(msg)

def _handle_PacketIn(event):
    dpid = event.connection.dpid
    sw=dpidToStr(dpid)
    inport = event.port
    eth_packet = event.parsed
    log.debug("Event: switch %s port %s packet %s" % (sw, inport, eth_packet))

    table[(dpid,eth_packet.src)] = event.port
    dst_port = table.get((dpid,eth_packet.dst))

    if dst_port is None and eth_packet.type == eth.ARP_TYPE and eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff"):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
        return

    for rule in rules:
        if (eth_packet.dst==EthAddr(rule['EthDst']) and eth_packet.src==EthAddr(rule['EthSrc'])):
            log.debug("Applying rule from %s to %s" % (eth_packet.src, eth_packet.dst))
            msg = of.ofp_flow_mod()
            msg.match.dl_src = EthAddr(rule['EthSrc'])
            msg.match.dl_dst = EthAddr(rule['EthDst'])

            if rule['drop']:
                event.connection.send(msg)
                return

            if rule['TCPPort']:
                if isinstance(eth_packet, ip.ipv4) and eth_packet.protocol == ip.TCP_PROTOCOL:
                    tcp_packet = eth_packet.find('tcp')
                    if tcp_packet and tcp_packet.dstport == rule['TCPPort']:
                        msg.match.nw_proto = ip.TCP_PROTOCOL
                        msg.match.tp_dst = rule['TCPPort']

            if rule['queue'] is not None:
                msg.actions.append(of.ofp_action_enqueue(port=dst_port, queue_id=rule['queue']))
            else:
                msg.actions.append(of.ofp_action_output(port=dst_port))

            event.connection.send(msg)
            break

