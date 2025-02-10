from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os

def setup_qos():
    """ Configure QoS on the switch """
    info('*** Setting up QoS rules \n')
    os.system("sudo ovs-vsctl --all destroy qos")
    os.system("sudo ovs-vsctl --all destroy queue")
    
    # Create QoS rules and queues
    os.system("sudo ovs-vsctl set port s1-eth3 qos=@newqos -- "
              "--id=@newqos create qos type=linux-htb queues=0=@q0 "
              "--id=@q0 create queue other-config:min-rate=20000000 other-config:max-rate=30000000")
    os.system("sudo ovs-vsctl set port s1-eth2 qos=@newqos2 -- "
              "--id=@newqos2 create qos type=linux-htb queues=0=@q1 "
              "--id=@q1 create queue other-config:min-rate=50000000 other-config:max-rate=150000000")
    os.system("sudo ovs-vsctl set port s1-eth4 qos=@newqos3 -- "
              "--id=@newqos3 create qos type=linux-htb queues=0=@q2 "
              "--id=@q2 create queue other-config:min-rate=50000000 other-config:max-rate=200000000")

def topology():
    net = Mininet(controller=Controller, switch=OVSSwitch)
    info('*** Adding controller\n')
    net.addController('c0')

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4', mac='00:00:00:00:00:04')

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1')

    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info('*** Starting network\n')
    net.start()
    
    setup_qos()
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()

