"""
SDN Traffic Classifier - Mininet Topology
Creates a simple topology: 4 hosts connected to 1 OpenFlow switch.
Connects to a remote Ryu controller.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import argparse


def build_topology(controller_ip="127.0.0.1", controller_port=6633):
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Adding controller\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port
    )

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    h4 = net.addHost("h4", ip="10.0.0.4/24")

    info("*** Creating links\n")
    net.addLink(h1, s1, bw=10, delay="2ms")
    net.addLink(h2, s1, bw=10, delay="2ms")
    net.addLink(h3, s1, bw=10, delay="2ms")
    net.addLink(h4, s1, bw=10, delay="2ms")

    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])

    info("*** Network started. Topology:\n")
    info("    h1 (10.0.0.1) ─┐\n")
    info("    h2 (10.0.0.2) ─┤── s1 ── [Ryu Controller @ {}:{}]\n".format(
        controller_ip, controller_port))
    info("    h3 (10.0.0.3) ─┤\n")
    info("    h4 (10.0.0.4) ─┘\n")

    info("*** Running CLI (type 'exit' to quit)\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDN Traffic Classifier Topology")
    parser.add_argument("--controller-ip",   default="127.0.0.1", help="Ryu controller IP")
    parser.add_argument("--controller-port", default=6633, type=int, help="Ryu controller port")
    args = parser.parse_args()

    setLogLevel("info")
    build_topology(args.controller_ip, args.controller_port)
