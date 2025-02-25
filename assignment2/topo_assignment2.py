from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import os

def assignmentTopo():
    net = Mininet( controller=RemoteController)
    ######################################################################################
    ############ CODE SHOULD ONLY BE ADDED BELOW  #################################
    info( '*** Adding controller\n' )
    # => add the controller here
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'h1', ip='10.0.0.1', mac='00:00:00:00:00:01' )
    # => h1 is already added, now add the other hosts here
    h2 = net.addHost( 'h2', ip='10.0.0.2', mac='00:00:00:00:00:02' )
    h3 = net.addHost( 'h3', ip='10.0.0.3', mac='00:00:00:00:00:03' )
    h4 = net.addHost( 'h4', ip='10.0.0.4', mac='00:00:00:00:00:04' )

    info( '*** Adding switches\n' )
    # => add the switches here
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )

    info( '*** Creating links\n' )
    # => create the links here
    net.addLink(h1, s1)   # s1-eth1
    net.addLink(h2, s1)   # s1-eth2
    net.addLink(s1, s2)   # s1-eth3, s2-eth3
    net.addLink(h3, s2)   # s2-eth1
    net.addLink(h4, s2)   # s2-eth2

    info( '*** Starting network\n')
    net.start()
    h1, h2, h3, h4 = net.hosts[0], net.hosts[1], net.hosts[2], net.hosts[3]

    # => fill in here command to add two queues to the correct port of the correct switch:
    # Q0 => 20..30 Mbps, Q1 => 50..150 Mbps for traffic from H1
    os.system("sudo ovs-vsctl set port s1-eth1 qos=@newqos1 -- "
              "--id=@newqos1 create qos type=linux-htb queues=0=@q0,1=@q1 -- "
              "--id=@q0 create queue other-config:min-rate=20000000 other-config:max-rate=30000000 -- "
              "--id=@q1 create queue other-config:min-rate=50000000 other-config:max-rate=150000000")

    # => fill in here command to add one queue to s1-eth2 (for H2 -> somewhere):
    # Q0 => 20..200 Mbps
    os.system("sudo ovs-vsctl set port s1-eth2 qos=@newqos2 -- "
              "--id=@newqos2 create qos type=linux-htb queues=0=@q0 -- "
              "--id=@q0 create queue other-config:min-rate=20000000 other-config:max-rate=200000000")

    # => fill in here command to add two queues to s2-eth2 (for H4), so you can shape H2->H4 at 200Mb if you like
    os.system("sudo ovs-vsctl set port s2-eth2 qos=@newqos3 -- "
              "--id=@newqos3 create qos type=linux-htb queues=0=@q0,1=@q1 -- "
              "--id=@q0 create queue other-config:min-rate=20000000 other-config:max-rate=200000000 -- "
              "--id=@q1 create queue other-config:min-rate=50000000 other-config:max-rate=1000000000000")


    ########### THIS IS THE END OF THE AREA WHERE YOU NEED TO ADD CODE ##################################
    #####################################################################################################
    # The lines below run tests automatically:

    # Reduce TCP retries to speed up testing
    h1.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h1.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')
    h2.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h2.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')
    h3.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h3.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')
    h4.cmd('sudo sysctl -w net.ipv4.tcp_syn_retries=1')
    h4.cmd('sudo sysctl -w net.ipv4.tcp_retries=1')

    info( '\n\n\n\n*** Testing CIR from H1 to H3 port 40 - should be capped at 30Mb/s\n')
    h3.cmd('iperf -s -p40 &')
    print(h1.cmd('iperf -c %s -p40' % h3.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing CIR from H1 to H2 port 60 - should be capped at 150Mb/s\n')
    h2.cmd('iperf -s -p60 &')
    print(h1.cmd('iperf -c %s -p60' % h2.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing CIR from H1 to H4 - should not be capped\n')
    h4.cmd('iperf -s &')
    print(h1.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing CIR from H2 to H4 - should be capped at 200Mb/s\n')
    print(h2.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing CIR from H4 to H1 - should not be capped\n')
    h1.cmd('iperf -s &')
    print(h4.cmd('iperf -c %s' % h1.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing link from H3 to H4 - should be blocked\n')
    print(h3.cmd('iperf -c %s' % h4.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing link from H4 to H2 - should be uncapped\n')
    print(h4.cmd('iperf -c %s -p60' % h2.IP()))
    time.sleep(3)

    info( '\n\n\n\n*** Testing link from H4 to H3 - should be blocked\n')
    print(h4.cmd('iperf -c %s -p40' % h3.IP()))
    time.sleep(1)

    CLI( net )

    # Cleanup QoS
    os.system('sudo ovs-vsctl clear Port s1-eth1 qos')
    os.system('sudo ovs-vsctl clear Port s1-eth2 qos')
    os.system('sudo ovs-vsctl clear Port s1-eth3 qos')
    os.system('sudo ovs-vsctl clear Port s2-eth1 qos')
    os.system('sudo ovs-vsctl clear Port s2-eth2 qos')
    os.system('sudo ovs-vsctl clear Port s2-eth3 qos')
    os.system('sudo ovs-vsctl --all destroy qos')
    os.system('sudo ovs-vsctl --all destroy queue')

    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    assignmentTopo()
