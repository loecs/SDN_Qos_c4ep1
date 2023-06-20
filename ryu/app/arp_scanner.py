from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.lib.packet import packet, arp, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.base import app_manager
from ryu.topology.api import get_switch
from ryu.lib import hub
import time


class ARPScanner(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARPScanner, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.mac_to_port = {}
        self.hosts = {}
        self.hold_down_expired = 10
        self.scan_interval_sec = 5
        self.arp_thread = hub.spawn(self.start_scanner)

    def add_host(self, ip, mac, port, dp_id):
        if mac in self.hosts:
            if self.hosts[mac]['last_updated'] > time.time() - self.hold_down_expired:
                return
        self.logger.info('Adding new host %s %s %s', ip, mac, port)
        self.hosts[mac] = {'last_updated': time.time(), 'ip': ip, 'port': port, 'dp_id': dp_id}

    def handle_arp(self, msg):
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return
        arp_reply = arp.arp(hwtype=arp_pkt.hwtype, proto=arp_pkt.proto, hlen=arp_pkt.hlen, plen=arp_pkt.plen,
                            opcode=arp.ARP_REPLY,
                            src_mac=arp_pkt.dst_mac, src_ip=arp_pkt.dst_ip, dst_mac=arp_pkt.src_mac,
                            dst_ip=arp_pkt.src_ip)
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dst=arp_pkt.src_mac, src=arp_pkt.dst_mac, ethertype=ethernet.ether.ETH_TYPE_ARP))
        pkt.add_protocol(arp_reply)
        pkt.serialize()
        data = pkt.data
        actions = [msg.datapath.ofproto_parser.OFPActionOutput(msg.match['in_port'])]
        out = msg.datapath.ofproto_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER,
                                                           in_port=msg.match['in_port'],
                                                           actions=actions, data=data)
        msg.datapath.send_msg(out)

    def send_arp_request(self, datapath, port, ip):
        if not self.mac_to_port[datapath.id][port]:
            return
        e = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=list(self.mac_to_port[datapath.id][port])[0])
        a = arp.arp(1, 0x0800, 6, 4, 1, list(self.mac_to_port[datapath.id][port])[0], ip,
                    list(self.mac_to_port[datapath.id][port])[0], ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        datapath.send_packet_out(port=port, data=p.data)

    def scan_hosts(self):
        for dp in get_switch(self.topology_api_app):
            datapath = dp.dp
            self.mac_to_port[datapath.id] = {}
            for port in range(1, len(datapath.ports) + 1):
                self.mac_to_port[datapath.id][port] = {}
                for hostip in self.hosts.values():
                    self.logger.info('Sending ARP request to %s', hostip['ip'])
                    self.send_arp_request(datapath, port, hostip['ip'])


    def start_scanner(self):
        while True:
            if self.hosts:
                print('Start scanning...')
                self.scan_hosts()
                print('Scan finished.All hosts are up to date.')
                time.sleep(self.scan_interval_sec)
            else:
                print('No hosts to scan.')
                time.sleep(self.scan_interval_sec)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst

        if dst == "ff:ff:ff:ff:ff:ff":
            return

        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id].setdefault(in_port, {})
        self.mac_to_port[datapath.id][in_port][src] = time.time()

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                self.handle_arp(msg)
            else:
                return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.add_host(ip_pkt.src, src, in_port, datapath.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.logger.info("Switch connected: datapath id = %016x", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPortStatus, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                               DEAD_DISPATCHER])
    def port_status_handler(self, ev):
        msg = ev.msg
        dp_id = msg.datapath.id
        if dp_id not in self.mac_to_port:
            return
        port_no = msg.desc.port_no
        ofproto = msg.datapath.ofproto
        if msg.reason == ofproto.OFPPR_DELETE:
            self.logger.info("Port deleted: datapath id = %016x, port no = %d", dp_id, port_no)
            for mac, host in self.hosts.items():
                if host['dp_id'] == dp_id and host['port'] == port_no:
                    self.logger.info("Deleting host %s %s", host['ip'], mac)
                    del self.hosts[mac]

