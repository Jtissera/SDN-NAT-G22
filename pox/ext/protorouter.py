from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp, echo

log = core.getLogger()

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK = 24
PRIVATE_IP = IPAddr("192.168.1.254")
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")

PUBLIC_IP = IPAddr("200.0.0.254")
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")
PUBLIC_PORT = 1

NAT_PORT_MIN = 10000
NAT_PORT_MAX = 65000

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

FLOW_IDLE_TIMEOUT = 30


class ProtoRouter(object):

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.arp_table = {}
        self.arp_pending = {}
        self.nat_outbound = {}
        self.nat_inbound = {}

        self.port_pool = set(range(NAT_PORT_MIN, NAT_PORT_MAX + 1))

        log_color(
            GREEN,
            f"ProtoRouter inicializado | Pool: {len(self.port_pool)} puertos disponibles",
        )

    def allocate_port(self):
        if not self.port_pool:
            log_color(RED, "ERROR: pool de puertos NAT agotado")
            return None
        port = min(self.port_pool)
        self.port_pool.remove(port)
        return port

    def release_port(self, port):
        self.port_pool.add(port)
        log_color(
            CYAN, f"Puerto {port} devuelto al pool | disponibles: {len(self.port_pool)}"
        )

    def nat_lookup_outbound(self, ip_src, port_src):
        return self.nat_outbound.get((ip_src, port_src))

    def nat_create_entry(self, ip_src, port_src, in_port):
        nat_port = self.allocate_port()
        if nat_port is None:
            return None
        self.nat_outbound[(ip_src, port_src)] = nat_port
        self.nat_inbound[nat_port] = (ip_src, port_src, in_port)
        log_color(
            GREEN,
            f"NAT NUEVA ENTRADA | {ip_src}:{port_src} → puerto NAT={nat_port} | in_port={in_port}",
        )
        return nat_port

    def nat_lookup_inbound(self, nat_port):
        return self.nat_inbound.get(nat_port)

    def nat_remove_entry(self, nat_port):
        entry = self.nat_inbound.pop(nat_port, None)
        if entry is None:
            return
        ip_src, port_src, in_port = entry
        self.nat_outbound.pop((ip_src, port_src), None)
        self.release_port(nat_port)
        log_color(
            YELLOW, f"NAT ENTRADA ELIMINADA | {ip_src}:{port_src} puerto NAT={nat_port}"
        )

    def send_arp_reply(self, request_arp, our_mac, out_port):
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = our_mac
        arp_reply.hwdst = request_arp.hwsrc
        arp_reply.protosrc = request_arp.protodst
        arp_reply.protodst = request_arp.protosrc

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = our_mac
        eth.dst = request_arp.hwsrc
        eth.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

        log_color(
            CYAN,
            f"ARP REPLY | {arp_reply.protosrc} es {our_mac} → {arp_reply.protodst} | out_port={out_port}",
        )

    def send_arp_request(self, ip_dst, ip_src, mac_src, out_port):
        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.hwsrc = mac_src
        arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        arp_req.protosrc = ip_src
        arp_req.protodst = ip_dst

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = mac_src
        eth.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

        log_color(CYAN, f"ARP REQUEST | ¿Quién tiene {ip_dst}? | out_port={out_port}")

    def flush_arp_pending(self, ip):
        """
        Reenvía todos los paquetes que estaban esperando la MAC de ip.
        Llamado cuando aprendemos una nueva MAC via ARP Reply.
        """
        pending = self.arp_pending.pop(ip, [])
        if not pending:
            return

        log_color(
            CYAN,
            f"ARP FLUSH | {len(pending)} paquete(s) pendiente(s) para {ip}",
        )

        for event, out_port, src_mac in pending:
            self.handle_ip(event)

    def enqueue_pending(self, ip_dst, event, out_port, src_mac):
        """
        Encola un paquete en espera de resolución ARP para ip_dst.
        Si es la primera vez que esperamos esa IP, lanza un ARP Request.
        """
        already_waiting = ip_dst in self.arp_pending
        self.arp_pending.setdefault(ip_dst, []).append((event, out_port, src_mac))

        if not already_waiting:
            # Primera vez que esperamos esta IP: mandamos el ARP Request
            if ip_dst.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
                self.send_arp_request(ip_dst, PRIVATE_IP, PRIVATE_MAC, out_port)
            else:
                self.send_arp_request(ip_dst, PUBLIC_IP, PUBLIC_MAC, PUBLIC_PORT)

    def get_transport_ports(self, ip_pkt):
        """
        Extrae (src_port, dst_port) del payload IP según el protocolo.
        Para ICMP usa el campo 'id' del echo como identificador de sesión.
        Retorna (None, None) si el protocolo no es soportado.
        """
        proto = ip_pkt.protocol

        if proto == PROTO_TCP:
            tcp = ip_pkt.payload
            return tcp.srcport, tcp.dstport

        elif proto == PROTO_UDP:
            udp = ip_pkt.payload
            return udp.srcport, udp.dstport

        elif proto == PROTO_ICMP:
            icmp = ip_pkt.payload
            # Solo procesamos Echo Request (type=8) y Echo Reply (type=0)
            if icmp.type in (0, 8):
                return icmp.payload.id, icmp.payload.id
            return None, None

        return None, None

    def install_outbound_flow(
        self, ip_src, port_src, ip_dst, port_dst, proto, nat_port, mac_dst, in_port
    ):
        """
        Instala regla en el switch para tráfico saliente de esta conexión.
        Match: paquetes desde ip_src:port_src hacia ip_dst:port_dst
        Action: reescribir IP y puerto origen, reescribir MACs, salir por PUBLIC_PORT
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_IDLE_TIMEOUT
        fm.flags = of.OFPFF_SEND_FLOW_REM  # notificar cuando expire

        fm.match.dl_type = 0x0800
        fm.match.nw_proto = proto
        fm.match.nw_src = ip_src
        fm.match.nw_dst = ip_dst
        fm.match.in_port = in_port

        if proto in (PROTO_TCP, PROTO_UDP):
            fm.match.tp_src = port_src
            fm.match.tp_dst = port_dst

        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))

        if proto in (PROTO_TCP, PROTO_UDP):
            fm.actions.append(of.ofp_action_tp_port.set_src(nat_port))

        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(mac_dst))

        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))

        self.connection.send(fm)
        log_color(
            GREEN,
            f"FLUJO SALIENTE instalado | {ip_src}:{port_src} → {ip_dst}:{port_dst} "
            f"[proto={proto}] nat_port={nat_port}",
        )

    def install_inbound_flow(
        self, nat_port, ip_priv, port_priv, ip_src, port_src, proto, mac_priv, out_port
    ):
        """
        Instala regla en el switch para tráfico entrante de esta conexión.
        Match: paquetes desde ip_src:port_src hacia PUBLIC_IP:nat_port
        Action: reescribir IP y puerto destino, reescribir MACs, salir por out_port
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_IDLE_TIMEOUT
        fm.flags = of.OFPFF_SEND_FLOW_REM

        fm.match.dl_type = 0x0800
        fm.match.nw_proto = proto
        fm.match.nw_src = ip_src
        fm.match.nw_dst = PUBLIC_IP
        fm.match.in_port = PUBLIC_PORT

        if proto in (PROTO_TCP, PROTO_UDP):
            fm.match.tp_src = port_src
            fm.match.tp_dst = nat_port

        fm.actions.append(of.ofp_action_nw_addr.set_dst(ip_priv))

        if proto in (PROTO_TCP, PROTO_UDP):
            fm.actions.append(of.ofp_action_tp_port.set_dst(port_priv))

        fm.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))

        fm.actions.append(of.ofp_action_dl_addr.set_dst(mac_priv))
        fm.actions.append(of.ofp_action_output(port=out_port))

        self.connection.send(fm)
        log_color(
            GREEN,
            f"FLUJO ENTRANTE instalado | {ip_src}:{port_src} → {ip_priv}:{port_priv} "
            f"[proto={proto}] nat_port={nat_port}",
        )

    def forward_outbound(self, event, ip_pkt, port_src, nat_port, mac_dst):
        """
        Reenvía el primer paquete saliente con las traducciones aplicadas.
        Los paquetes posteriores de la misma conexión los maneja el flujo instalado.
        """
        pkt = event.parsed

        ip_pkt.srcip = PUBLIC_IP
        ip_pkt.csum = 0

        proto = ip_pkt.protocol
        if proto == PROTO_TCP:
            ip_pkt.payload.srcport = nat_port
            ip_pkt.payload.csum = 0
        elif proto == PROTO_UDP:
            ip_pkt.payload.srcport = nat_port
            ip_pkt.payload.csum = 0

        pkt.src = PUBLIC_MAC
        pkt.dst = mac_dst

        msg = of.ofp_packet_out()
        msg.data = pkt.pack()
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)
        log_color(
            CYAN,
            f"REENVÍO SALIENTE | {PUBLIC_IP}:{nat_port} → {ip_pkt.dstip} | out_port={PUBLIC_PORT}",
        )

    def forward_inbound(
        self, event, ip_pkt, nat_port, ip_priv, port_priv, mac_priv, out_port
    ):
        """
        Reenvía el primer paquete entrante con las traducciones aplicadas.
        """
        pkt = event.parsed

        ip_pkt.dstip = ip_priv
        ip_pkt.csum = 0

        proto = ip_pkt.protocol
        if proto == PROTO_TCP:
            ip_pkt.payload.dstport = port_priv
            ip_pkt.payload.csum = 0
        elif proto == PROTO_UDP:
            ip_pkt.payload.dstport = port_priv
            ip_pkt.payload.csum = 0

        pkt.src = PRIVATE_MAC
        pkt.dst = mac_priv

        msg = of.ofp_packet_out()
        msg.data = pkt.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        log_color(
            CYAN,
            f"REENVÍO ENTRANTE | {ip_pkt.srcip} → {ip_priv}:{port_priv} | out_port={out_port}",
        )

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] Trama no reconocida por POX.")
            return

        pkt_type = event.parsed.type

        if pkt_type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        elif pkt_type == ethernet.IP_TYPE:
            self.handle_ip(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: tipo Ethernet 0x{pkt_type:04x}")

    def _handle_FlowRemoved(self, event):
        """
        El switch notifica que un flujo expiró por idle_timeout.
        Liberamos el puerto NAT correspondiente.
        """
        match = event.ofp.match

        if match.nw_dst == PUBLIC_IP and match.tp_dst is not None:
            self.nat_remove_entry(match.tp_dst)

    def handle_arp(self, event):
        packet = event.parsed
        arp_pkt = packet.payload
        in_port = event.port

        if arp_pkt.protosrc not in self.arp_table:
            self.arp_table[arp_pkt.protosrc] = arp_pkt.hwsrc
            log_color(GREEN, f"ARP LEARN | {arp_pkt.protosrc} → {arp_pkt.hwsrc}")

        if arp_pkt.opcode == arp.REQUEST:
            log_color(
                YELLOW,
                f"ARP REQUEST | ¿Quién tiene {arp_pkt.protodst}? | de {arp_pkt.protosrc} | in_port={in_port}",
            )
            if arp_pkt.protodst == PRIVATE_IP:
                self.send_arp_reply(arp_pkt, PRIVATE_MAC, in_port)
            elif arp_pkt.protodst == PUBLIC_IP:
                self.send_arp_reply(arp_pkt, PUBLIC_MAC, in_port)
            else:
                log_color(
                    YELLOW, f"ARP REQUEST ignorado: {arp_pkt.protodst} no es nuestra IP"
                )

        elif arp_pkt.opcode == arp.REPLY:
            log_color(
                GREEN,
                f"ARP REPLY | {arp_pkt.protosrc} tiene MAC {arp_pkt.hwsrc} | in_port={in_port}",
            )
            self.flush_arp_pending(arp_pkt.protosrc)

        else:
            log_color(YELLOW, f"ARP opcode desconocido: {arp_pkt.opcode}")

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        if ip_pkt.dstip in (PRIVATE_IP, PUBLIC_IP):
            if ip_pkt.protocol == PROTO_ICMP:
                self.handle_icmp_to_router(event, packet, ip_pkt, in_port)
            else:
                log_color(
                    YELLOW, f"Paquete dirigido al router ({ip_pkt.dstip}), descartando"
                )
            return

        proto = ip_pkt.protocol
        if proto not in (PROTO_TCP, PROTO_UDP, PROTO_ICMP):
            log_color(YELLOW, f"Protocolo IP no soportado: {proto}")
            return

        port_src, port_dst = self.get_transport_ports(ip_pkt)
        if port_src is None:
            log_color(YELLOW, f"ICMP tipo no soportado, ignorando")
            return

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            self.handle_outbound(
                event, packet, ip_pkt, in_port, proto, port_src, port_dst
            )
        else:
            self.handle_inbound(
                event, packet, ip_pkt, in_port, proto, port_src, port_dst
            )

    def handle_icmp_to_router(self, event, packet, ip_pkt, in_port):
        """
        Responde ICMP Echo Request dirigidos a las IPs del router.
        Construye un Echo Reply invirtiendo src/dst.
        """

        icmp_pkt = ip_pkt.payload
        if icmp_pkt.type != 8:
            log_color(YELLOW, f"ICMP tipo {icmp_pkt.type} al router, descartando")
            return

        if ip_pkt.dstip == PRIVATE_IP:
            our_mac = PRIVATE_MAC
        else:
            our_mac = PUBLIC_MAC

        icmp_reply = icmp()
        icmp_reply.type = 0  # Echo Reply
        icmp_reply.payload = icmp_pkt.payload

        ip_reply = ipv4()
        ip_reply.srcip = ip_pkt.dstip
        ip_reply.dstip = ip_pkt.srcip
        ip_reply.protocol = PROTO_ICMP
        ip_reply.payload = icmp_reply

        eth_reply = ethernet()
        eth_reply.type = ethernet.IP_TYPE
        eth_reply.src = our_mac
        eth_reply.dst = packet.src
        eth_reply.payload = ip_reply

        msg = of.ofp_packet_out()
        msg.data = eth_reply.pack()
        msg.actions.append(of.ofp_action_output(port=in_port))
        self.connection.send(msg)

        log_color(
            CYAN, f"ICMP REPLY | {ip_pkt.dstip} → {ip_pkt.srcip} | out_port={in_port}"
        )

    def handle_outbound(
        self, event, packet, ip_pkt, in_port, proto, port_src, port_dst
    ):
        """
        Paquete saliente: viene de la red privada hacia la pública.
        1. Busca o crea entrada NAT
        2. Resuelve MAC de destino (o encola si no la tiene)
        3. Instala flujos y reenvía el paquete actual
        """
        ip_src = ip_pkt.srcip
        ip_dst = ip_pkt.dstip

        nat_port = self.nat_lookup_outbound(ip_src, port_src)
        if nat_port is None:
            nat_port = self.nat_create_entry(ip_src, port_src, in_port)
            if nat_port is None:
                log_color(RED, "DROP: pool de puertos agotado")
                return

        log_color(
            YELLOW,
            f"SALIENTE | {ip_src}:{port_src} → {ip_dst}:{port_dst} "
            f"[proto={proto}] nat_port={nat_port}",
        )

        mac_dst = self.arp_table.get(ip_dst)
        if mac_dst is None:
            log_color(
                YELLOW, f"MAC de {ip_dst} desconocida, encolando y mandando ARP Request"
            )
            self.enqueue_pending(ip_dst, event, PUBLIC_PORT, PUBLIC_MAC)
            return

        self.install_outbound_flow(
            ip_src, port_src, ip_dst, port_dst, proto, nat_port, mac_dst, in_port
        )
        self.install_inbound_flow(
            nat_port, ip_src, port_src, ip_dst, port_dst, proto, packet.src, in_port
        )
        self.forward_outbound(event, ip_pkt, port_src, nat_port, mac_dst)

    def handle_inbound(self, event, packet, ip_pkt, in_port, proto, port_src, port_dst):
        """
        Paquete entrante: viene de la red pública hacia la pública.
        1. Busca entrada NAT usando el puerto destino
        2. Resuelve MAC del host privado (o encola si no la tiene)
        3. Instala flujos y reenvía el paquete actual
        """
        ip_src = ip_pkt.srcip

        nat_port = port_dst

        entry = self.nat_lookup_inbound(nat_port)
        if entry is None:
            log_color(
                RED,
                f"DROP: no hay entrada NAT para puerto {nat_port} (tráfico no solicitado)",
            )
            return

        ip_priv, port_priv, out_port = entry

        log_color(
            YELLOW,
            f"ENTRANTE | {ip_src}:{port_src} → NAT:{nat_port} "
            f"→ {ip_priv}:{port_priv} [proto={proto}]",
        )

        mac_priv = self.arp_table.get(ip_priv)
        if mac_priv is None:
            log_color(
                YELLOW,
                f"MAC de {ip_priv} desconocida, encolando y mandando ARP Request",
            )
            self.enqueue_pending(ip_priv, event, out_port, PRIVATE_MAC)
            return

        self.install_inbound_flow(
            nat_port, ip_priv, port_priv, ip_src, port_src, proto, mac_priv, out_port
        )
        self.install_outbound_flow(
            ip_priv, port_priv, ip_src, port_src, proto, nat_port, packet.src, out_port
        )
        self.forward_inbound(
            event, ip_pkt, nat_port, ip_priv, port_priv, mac_priv, out_port
        )


def launch():
    def start_switch(event):
        log_color(YELLOW, f"Switch conectado: dpid={event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
