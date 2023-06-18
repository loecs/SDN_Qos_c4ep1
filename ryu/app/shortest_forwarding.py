# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# conding=utf-8
import ast
import logging
import math
import struct
import networkx as nx
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, in_proto
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, icmp, tcp, udp
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import setting
import discover
import monitor
import detector
import pymysql

CONF = cfg.CONF


class ShortestForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "discover": discover.Discover,
        "monitor": monitor.Monitor,
        "detector": detector.Detector}

    WEIGHT_MODEL = {'hop': 'weight', 'delay': "delay"}

    def __init__(self, *args, **kwargs):
        super(ShortestForwarding, self).__init__(*args, **kwargs)
        self.name = 'shortest_forwarding'
        self.discover = kwargs["discover"]
        self.monitor = kwargs["monitor"]
        self.detector = kwargs["detector"]
        self.datapaths = {}
        self.weight = self.WEIGHT_MODEL[CONF.weight]
        self.db = pymysql.connect(host='192.168.50.133',
                                  port=3306,
                                  user='c4bep1',
                                  password='c4bep1',
                                  database='c4bep1')

    def set_weight_mode(self, weight):

        self.weight = weight
        if self.weight == self.WEIGHT_MODEL['hop']:
            self.discover.get_shortest_paths(weight=self.weight)
        return True

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):

        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):

        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port, ip_protocol=None, idle_timeout=15,
                      hard_timeout=60):
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))
        match = parser.OFPMatch()
        if ip_protocol is None:

            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
        elif ip_protocol['ip_proto'] == in_proto.IPPROTO_ICMP:
            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                ip_proto=ip_protocol['ip_proto'], icmpv4_code=ip_protocol['icmpv4_code'],
                icmpv4_type=ip_protocol['icmpv4_type'])
        elif ip_protocol['ip_proto'] == in_proto.IPPROTO_TCP:
            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                ip_proto=ip_protocol['ip_proto'], tcp_src=ip_protocol['tcp_src'],
                tcp_dst=ip_protocol['tcp_dst'])
        elif ip_protocol['ip_proto'] == in_proto.IPPROTO_UDP:
            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                ip_proto=ip_protocol['ip_proto'], udp_src=ip_protocol['udp_src'],
                udp_dst=ip_protocol['udp_dst'])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=idle_timeout, hard_timeout=hard_timeout)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):

        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            return None

    def flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.discover.access_ports:
            for port in self.discover.access_ports[dpid]:
                if (dpid, port) not in self.discover.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.discover.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
        else:
            self.flood(msg)

    def get_path(self, src, dst, ip_tos):

        shortest_paths = self.discover.shortest_paths
        graph = self.discover.graph

        # print(shortest_paths.get(src).get(dst))
        if ip_tos != 0:
            path = self.paths_qos(src, dst, ip_tos)
            if path is not None:
                path = ast.literal_eval(path)
                return path
        return shortest_paths.get(src).get(dst)[0]

    def get_bw(self, pairs):
        cursor = self.db.cursor()
        bw = {}
        for link in pairs:
            src = link[0]
            dst = link[1]

            cursor.execute("select * from link where src_dpid=%s and dst_dpid=%s", (src, dst))
            if cursor.fetchone() is None:
                src, dst = dst, src

            cursor.execute("select link_bandwidth from link where src_dpid=%s and dst_dpid=%s", (src, dst))
            bw[link] = int(cursor.fetchone()[0])
        cursor.close()
        return bw

    def links_qos(self, pairs):
        link_stat = self.discover.link_stat
        bw = self.get_bw(pairs)
        free_bw = []
        delay = []
        jitter = []
        loss = []

        for link in pairs:
            if link in link_stat:
                # free_bw.append(bw[link] - (link_stat[link]['throughput'] / 1000000))
                free_bw.append(100 - (link_stat[link]['throughput'] / 1000000))
                delay.append(link_stat[link]['delay'])
                jitter.append(link_stat[link]['jitter'])
                loss.append(link_stat[link]['loss'])
        link_qos = {'free_bw': free_bw, 'delay': delay, 'jitter': jitter, 'loss': loss}
        '''
        print(pairs)
        print(free_bw)
        print(delay)
        print(jitter)
        print(loss)
        '''
        return link_qos

    def paths_free_bw(self, free_bw):
        path_free_bw = min(free_bw)
        return path_free_bw

    def paths_delay(self, delay):
        path_delay = sum(delay)
        return path_delay

    def paths_jitter(self, jitter):

        path_jitter = 1
        for i in jitter:
            path_jitter = path_jitter * (1 - i)
        path_jitter = 1 - path_jitter
        if path_jitter < 0:
            path_jitter = 999
        return path_jitter

    def paths_loss(self, loss):
        path_loss = 1
        for i in loss:
            path_loss = path_loss * (1 - i)
        path_loss = 1 - path_loss
        if path_loss < 0:
            path_loss = 100
        return path_loss

    def bandwidth_utility(self, x, B, A, c):
        return 100 / (1 + B * math.exp(-A * x + c))

    def delay_utility(self, x, B, y1, y2, c1, c2, b1, b2, b3, delta):
        if x < c1:
            return 100 - y1 * x
        elif c1 <= x <= c2:
            return b1 * math.tanh(B * (x - b2)) + b3
        else:
            return delta - y2 * x

    def jitter_utility(self, x, b1, b2, b3, B):
        return b1 * math.tanh(B * (x - b2)) + b3

    def loss_utility(self, x, b1, b2, b3, B):
        return b1 - b2 * math.log(b3 + B * x)

    def paths_qos(self, src, dst, ip_tos):
        shortest_paths = self.discover.shortest_paths
        paths = shortest_paths.get(src).get(dst)
        path_utility = {}
        print('tos:' + str(ip_tos))
        for path in paths:
            pairs = list(zip(path, path[1:]))
            link_qos = self.links_qos(pairs)
            if not link_qos['free_bw']:
                continue
            path_free_bw = self.paths_free_bw(link_qos['free_bw'])
            path_delay = self.paths_delay(link_qos['delay'])
            path_jitter = self.paths_jitter(link_qos['jitter'])
            path_loss = self.paths_loss(link_qos['loss'])

            # path_qos[str(path)] = {'free_bw': path_free_bw, 'delay': path_delay, 'jitter': path_jitter,'loss': path_loss}
            qos_bw = None
            qos_delay = None
            qos_jitter = None
            qos_loss = None
            utility_value = 0
            if ip_tos == setting.SESSION_TOS:
                qos_bw = self.bandwidth_utility(path_free_bw, setting.SESSION_BW_MEASURE['B'],
                                                setting.SESSION_BW_MEASURE['A'], setting.SESSION_BW_MEASURE['c'])
                qos_delay = self.delay_utility(path_delay, setting.SESSION_DELAY_MEASURE['B'],
                                               setting.SESSION_DELAY_MEASURE['y1'],
                                               setting.SESSION_DELAY_MEASURE['y2'], setting.SESSION_DELAY_MEASURE['c1'],
                                               setting.SESSION_DELAY_MEASURE['c2'], setting.SESSION_DELAY_MEASURE['b1'],
                                               setting.SESSION_DELAY_MEASURE['b2'], setting.SESSION_DELAY_MEASURE['b3'],
                                               setting.SESSION_DELAY_MEASURE['delta'])
                qos_jitter = self.jitter_utility(path_jitter, setting.SESSION_JITTER_MEASURE['b1'],
                                                 setting.SESSION_JITTER_MEASURE['b2'],
                                                 setting.SESSION_JITTER_MEASURE['b3'],
                                                 setting.SESSION_JITTER_MEASURE['B'])
                qos_loss = self.loss_utility(path_loss, setting.SESSION_LOSS_MEASURE['b1'],
                                             setting.SESSION_LOSS_MEASURE['b2'],
                                             setting.SESSION_LOSS_MEASURE['b3'], setting.SESSION_LOSS_MEASURE['B'])
                utility_value = qos_bw * setting.SESSION_WEIGHT['BW'] + qos_delay * setting.SESSION_WEIGHT[
                    'DELAY'] + qos_jitter * setting.SESSION_WEIGHT['JITTER'] + qos_loss * setting.SESSION_WEIGHT['LOSS']

            elif ip_tos == setting.STREAMING_TOS:
                qos_bw = self.bandwidth_utility(path_free_bw, setting.STREAMING_BW_MEASURE['B'],
                                                setting.STREAMING_BW_MEASURE['A'], setting.STREAMING_BW_MEASURE['c'])
                qos_delay = self.delay_utility(path_delay, setting.STREAMING_DELAY_MEASURE['B'],
                                               setting.STREAMING_DELAY_MEASURE['y1'],
                                               setting.STREAMING_DELAY_MEASURE['y2'],
                                               setting.STREAMING_DELAY_MEASURE['c1'],
                                               setting.STREAMING_DELAY_MEASURE['c2'],
                                               setting.STREAMING_DELAY_MEASURE['b1'],
                                               setting.STREAMING_DELAY_MEASURE['b2'],
                                               setting.STREAMING_DELAY_MEASURE['b3'],
                                               setting.STREAMING_DELAY_MEASURE['delta'])
                qos_jitter = self.jitter_utility(path_jitter, setting.STREAMING_JITTER_MEASURE['b1'],
                                                 setting.STREAMING_JITTER_MEASURE['b2'],
                                                 setting.STREAMING_JITTER_MEASURE['b3'],
                                                 setting.STREAMING_JITTER_MEASURE['B'])
                qos_loss = self.loss_utility(path_loss, setting.STREAMING_LOSS_MEASURE['b1'],
                                             setting.STREAMING_LOSS_MEASURE['b2'],
                                             setting.STREAMING_LOSS_MEASURE['b3'], setting.STREAMING_LOSS_MEASURE['B'])
                utility_value = qos_bw * setting.STREAMING_WEIGHT['BW'] + qos_delay * setting.STREAMING_WEIGHT[
                    'DELAY'] + qos_jitter * setting.STREAMING_WEIGHT['JITTER'] + qos_loss * setting.STREAMING_WEIGHT[
                                    'LOSS']


            elif ip_tos == setting.OPERATE_TOS:
                qos_bw = self.bandwidth_utility(path_free_bw, setting.OPERATE_BW_MEASURE['B'],
                                                setting.OPERATE_BW_MEASURE['A'], setting.OPERATE_BW_MEASURE['c'])
                qos_delay = self.delay_utility(path_delay, setting.OPERATE_DELAY_MEASURE['B'],
                                               setting.OPERATE_DELAY_MEASURE['y1'],
                                               setting.OPERATE_DELAY_MEASURE['y2'], setting.OPERATE_DELAY_MEASURE['c1'],
                                               setting.OPERATE_DELAY_MEASURE['c2'], setting.OPERATE_DELAY_MEASURE['b1'],
                                               setting.OPERATE_DELAY_MEASURE['b2'], setting.OPERATE_DELAY_MEASURE['b3'],
                                               setting.OPERATE_DELAY_MEASURE['delta'])
                qos_loss = self.loss_utility(path_loss, setting.OPERATE_LOSS_MEASURE['b1'],
                                             setting.OPERATE_LOSS_MEASURE['b2'],
                                             setting.OPERATE_LOSS_MEASURE['b3'], setting.OPERATE_LOSS_MEASURE['B'])
                utility_value = qos_bw * setting.OPERATE_WEIGHT['BW'] + qos_delay * setting.OPERATE_WEIGHT[
                    'DELAY'] + qos_loss * setting.OPERATE_WEIGHT['LOSS']
            elif ip_tos == setting.DOWNLOAD_TOS:
                qos_bw = self.bandwidth_utility(path_free_bw, setting.DOWNLOAD_BW_MEASURE['B'],
                                                setting.DOWNLOAD_BW_MEASURE['A'], setting.DOWNLOAD_BW_MEASURE['c'])
                qos_loss = self.loss_utility(path_loss, setting.DOWNLOAD_LOSS_MEASURE['b1'],
                                             setting.DOWNLOAD_LOSS_MEASURE['b2'],
                                             setting.DOWNLOAD_LOSS_MEASURE['b3'], setting.DOWNLOAD_LOSS_MEASURE['B'])
                utility_value = qos_bw * setting.DOWNLOAD_WEIGHT['BW'] + qos_loss * setting.DOWNLOAD_WEIGHT['LOSS']
            else:
                return None
            path_utility[str(path)] = utility_value

        if not path_utility:
            return None

        path_utility = sorted(path_utility.items(), key=lambda item: item[1], reverse=True)
        print(path_utility)
        return path_utility[0][0]

    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None

        src_location = self.discover.get_host_location(src)
        if in_port in self.discover.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None

        dst_location = self.discover.get_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]

        return src_sw, dst_sw

    def install_flow(self, datapaths, link_to_port, access_table, path,
                     flow_info, buffer_id, data=None, ip_protocol=None):
        '''
            Install flow entires for roundtrip: go and back.
            @parameter: path=[dpid1, dpid2...]
                        flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        if path is None or len(path) == 0:
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])
        # inter_link
        if len(path) > 2:
            for i in xrange(1, len(path) - 1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i - 1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i + 1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port, ip_protocol)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port, ip_protocol)
        if len(path) > 1:
            # the last flow entry: tor -> host
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            src_port = port_pair[1]
            if flow_info[2].startswith(setting.SUBNET_PREFIX):
                dst_port = self.get_port(flow_info[2], access_table)
            else:
                dst_port = self.get_port(setting.GATEWAY_IP, access_table)
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return

            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port, ip_protocol)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port, ip_protocol)

            # the first flow entry
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port, ip_protocol)
            self.send_flow_mod(first_dp, back_info, out_port, in_port, ip_protocol)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

        # src and dst on the same datapath
        else:

            if flow_info[2].startswith(setting.SUBNET_PREFIX):
                out_port = self.get_port(flow_info[2], access_table)

            else:
                out_port = self.get_port(setting.GATEWAY_IP, access_table)

            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            self.send_flow_mod(first_dp, flow_info, in_port, out_port, ip_protocol)
            self.send_flow_mod(first_dp, back_info, out_port, in_port, ip_protocol)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst, ip_protocol=None, ip_tos=0):

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # Path has already calculated, just get it.
                path = self.get_path(src_sw, dst_sw, ip_tos)
                self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                flow_info = (eth_type, ip_src, ip_dst, in_port, ip_tos)

                self.install_flow(self.datapaths,
                                  self.discover.link_to_port,
                                  self.discover.access_table, path,
                                  flow_info, msg.buffer_id, msg.data, ip_protocol)
        return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            In packet_in handler, we need to learn access_table by ARP.
            Therefore, the first packet from UNKOWN host MUST be ARP.
        '''
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if isinstance(arp_pkt, arp.arp):
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):

            ip_dst = ip_pkt.dst
            ip_src = ip_pkt.src
            protocol = ip_pkt.proto
            if ip_dst.startswith('224.') or ip_dst.startswith('239.'):
                self.flood(msg)
                return

            ip_protocol = None
            # if ICMP Protocol
            if protocol == in_proto.IPPROTO_ICMP:
                t = pkt.get_protocol(icmp.icmp)
                ip_protocol = {'ip_proto': protocol, 'icmpv4_code': t.code, 'icmpv4_type': t.type}

            #  if TCP Protocol
            elif protocol == in_proto.IPPROTO_TCP:
                t = pkt.get_protocol(tcp.tcp)
                ip_protocol = {'ip_proto': protocol, 'tcp_src': t.src_port, 'tcp_dst': t.dst_port}

            #  If UDP Protocol
            elif protocol == in_proto.IPPROTO_UDP:
                u = pkt.get_protocol(udp.udp)
                ip_protocol = {'ip_proto': protocol, 'udp_src': u.src_port, 'udp_dst': u.dst_port}
            else:
                ip_protocol = {'ip_proto': protocol}

            if len(pkt.get_protocols(ethernet.ethernet)):
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst, ip_protocol, ip_pkt.tos)
