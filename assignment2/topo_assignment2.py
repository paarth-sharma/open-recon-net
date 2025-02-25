from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import os

def assignmentTopo():
    # Create a two-switch topology
    net = Mininet(controller=RemoteController)

    info('*** Adding controller\n')
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6633)

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:04')

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    info('*** Creating links\n')
    # h1 -> s1-eth1
    net.addLink(h1, s1)
    # h2 -> s1-eth2
    net.addLink(h2, s1)
    # s1 <-> s2 (assume s1-eth3 and s2-eth3)
    net.addLink(s1, s2)
    # h3 -> s2-eth1
    net.addLink(h3, s2)
    # h4 -> s2-eth2
    net.addLink(h4, s2)

    info('*** Starting network\n')
    net.start()

    # For convenience
    h1, h2, h3, h4 = net.hosts
    # We want:
    #  - 30Mb/s on s2-eth1 for H1->H3
    #  - 150Mb/s on s1-eth2 for H1->H2
    #  - 200Mb/s on s2-eth2 for H2->H4
    #  - Everything else is "uncapped"

    # 1) s2-eth1 => queue0 = 30Mb/s
    #    plus an uncapped queue1 if you want to handle H3->H1
    os.system(
        "ovs-vsctl set port s2-eth1 qos=@newqos1 -- "
        "--id=@newqos1 create qos type=linux-htb queues=0=@q0,1=@q1 -- "
        "--id=@q0 create queue other-config:min-rate=20000000 other-config:max-rate=30000000 -- "
        "--id=@q1 create queue other-config:min-rate=20000000 other-config:max-rate=1000000000000"
    )

    # 2) s1-eth2 => queue0 = uncapped, queue1 = 150Mb/s
    os.system(
        "ovs-vsctl set port s1-eth2 qos=@newqos2 -- "
        "--id=@newqos2 create qos type=linux-htb queues=0=@q0,1=@q1 -- "
        "--id=@q0 create queue other-config:min-rate=20000000 other-config:max-rate=1000000000000 -- "
        "--id=@q1 create queue other-config:min-rate=50000000 other-config:max-rate=150000000"
    )

    # 3) s2-eth2 => queue0 = uncapped, queue1 = 200Mb/s
    os.system(
        "ovs-vsctl set port s2-eth2 qos=@newqos3 -- "
        "--id=@newqos3 create qos type=linux-htb queues=0=@q0,1=@q1 -- "
        "--id=@q0 create queue other-config:min-rate=20000000 other-config:max-rate=1000000000000 -- "
        "--id=@q1 create queue other-config:min-rate=50000000 other-config:max-rate=200000000"
    )

    # Reduce TCP retries for quicker iperf tests
    for h in (h1, h2, h3, h4):
        h.cmd('sysctl -w net.ipv4.tcp_syn_retries=1')
        h.cmd('sysctl -w net.ipv4.tcp_retries=1')

    # Now run the assignment tests
    info('\n*** Testing CIR from H1 to H3 port 40 - should be ~30Mb/s\n')
    h3.cmd('iperf -s -p40 &')
    print(h1.cmd('iperf -c %s -p40' % h3.IP()))
    time.sleep(3)

    info('\n*** Testing CIR from H1 to H2 port 60 - should be ~150Mb/s\n')
    h2.cmd('iperf -s -p60 &')
    print(h1.cmd('iperf -c %s -p60' % h2.IP()))
    time.sleep(3)

    info('\n*** Testing CIR from H1 to H4 - should not be capped\n')
    h4.cmd('iperf -s &')
    print(h1.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info('\n*** Testing CIR from H2 to H4 - should be ~200Mb/s\n')
    print(h2.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info('\n*** Testing CIR from H4 to H1 - should not be capped\n')
    h1.cmd('iperf -s &')
    print(h4.cmd('iperf -c %s' % h1.IP()))
    time.sleep(3)

    info('\n*** Testing link from H3 to H4 - should be blocked\n')
    print(h3.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info('\n*** Testing link from H4 to H2 - should be uncapped\n')
    print(h4.cmd('iperf -c %s -p60' % h2.IP()))
    time.sleep(3)

    info('\n*** Testing link from H4 to H3 - should be blocked\n')
    print(h4.cmd('iperf -c %s -p40' % h3.IP()))
    time.sleep(1)

    CLI(net)

    # Cleanup QoS
    os.system('ovs-vsctl clear Port s1-eth1 qos')
    os.system('ovs-vsctl clear Port s1-eth2 qos')
    os.system('ovs-vsctl clear Port s1-eth3 qos')
    os.system('ovs-vsctl clear Port s2-eth1 qos')
    os.system('ovs-vsctl clear Port s2-eth2 qos')
    os.system('ovs-vsctl clear Port s2-eth3 qos')
    os.system('ovs-vsctl --all destroy qos')
    os.system('ovs-vsctl --all destroy queue')

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    assignmentTopo()
