#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel

#                                Red Pública            Red Privada
#
#                                  port 1                 port 2,3,4
#
#        ┌───────┐      200.0.0.254 / aa:aa:aa  192.168.1.254 / bb:bb:bb    ┌───────┐
#        │       │                         ┌───┐                            │  h2   │ 192.168.1.2
#        │  h1   ├─────────────────────────┤   ├────────────────────────────└───────┘
#        └───────┘                         │s1 ├────────────────┐           ┌───────┐
#     200.0.0.1/24                         │   │                │           │  h3   │ 192.168.1.3
#     GW: 200.0.0.254                      └───┘────────┐       └───────────└───────┘
#                                                       │                   ┌───────┐
#                                                       │                   │  h4   │ 192.168.1.4
#                                                       └───────────────────└───────┘
#
#


class NATTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")

        # Host público (servidor externo simulado)
        h1 = self.addHost(
            "h1",
            ip="200.0.0.1/24",
            mac="00:00:00:00:00:01",
            defaultRoute="via 200.0.0.254",
        )

        # Hosts privados (clientes detrás del NAT)
        h2 = self.addHost(
            "h2",
            ip="192.168.1.2/24",
            mac="00:00:00:00:00:02",
            defaultRoute="via 192.168.1.254",
        )

        h3 = self.addHost(
            "h3",
            ip="192.168.1.3/24",
            mac="00:00:00:00:00:03",
            defaultRoute="via 192.168.1.254",
        )

        h4 = self.addHost(
            "h4",
            ip="192.168.1.4/24",
            mac="00:00:00:00:00:04",
            defaultRoute="via 192.168.1.254",
        )

        # s1-eth1 → h1 (red pública)
        self.addLink(h1, s1)

        # s1-eth2, eth3, eth4 → h2, h3, h4 (red privada)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


def run():
    topo = NATTopo()
    net = Mininet(topo=topo, controller=RemoteController, link=TCLink)
    net.start()

    # Deshabilitar IPv6 en todos los hosts para evitar tráfico no deseado
    for host in net.hosts:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    # Deshabilitar IPv6 en el switch
    s1 = net.get("s1")
    s1.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    s1.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    s1.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
