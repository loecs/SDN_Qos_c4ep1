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

from __future__ import division
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology.api import get_link, get_switch
from ryu.topology.switches import Switches
from ryu.topology.switches import LLDPPacket
import networkx as nx
import time
import setting
import pymysql

CONF = cfg.CONF


class Detector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Detector, self).__init__(*args, **kwargs)

        self.name = 'detector'
        self.sending_echo_request_interval = 0.05
        # Get the active object of swicthes and discover module.
        # So that this module can use their data.
        self.sw_module = lookup_service_brick('switches')
        self.discover = lookup_service_brick('discover')

        self.datapaths = {}
        self.echo_latency = {}

        self.jitter_result = {}
        self.packets_result = {}
        self.loss_result = {}
        self.delay_result = {}
        self.measure_thread = hub.spawn(self._detector)

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

    def _detector(self):

        while True:
            self._send_echo_request()
            self.create_link_delay()
            self.get_loss()
            self.save_data()
            '''
            try:
                self.discover.shortest_paths = {}
                # Refresh
            except:
                self.discover = lookup_service_brick('discover')
            '''
            hub.sleep(setting.DELAY_DETECTING_PERIOD)

    def _send_echo_request(self):

        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath,
                                             data="%.12f" % time.time())
            datapath.send_msg(echo_req)

            hub.sleep(self.sending_echo_request_interval)

    def save_data(self):
        save_result = {}
        monitor = lookup_service_brick('monitor')
        for key, value in self.discover.link_to_port.items():
            src = key[0]
            dst = key[1]
            src_port = value[0]
            dst_port = value[1]
            key1 = "%s-%s-%s-%s" % (src, src_port, dst_port, dst)
            key2 = "%s-%s-%s-%s" % (dst, dst_port, src_port, src)
            temp_throughput = monitor.port_throughput[(src, src_port)][-1]

            self.discover.link_stat.setdefault((src, dst), {})
            self.discover.link_stat[(src, dst)] = {'throughput': temp_throughput,
                                                   'delay': self.delay_result[key1],
                                                   'jitter': self.jitter_result[key1],
                                                   'loss': self.loss_result[key1]}

            if src >= dst:
                continue
            save_result[key1] = {'throughput': temp_throughput,
                                 'delay': self.delay_result[key1],
                                 'jitter': self.jitter_result[key1], 'loss': self.loss_result[key1]}

        if save_result is not None:
            if setting.SAVE_SQL:
                self.save_sql(save_result)

    def save_sql(self, save_result):
        db = pymysql.connect(host='192.168.50.133',
                             port=3306,
                             user='c4bep1',
                             password='c4bep1',
                             database='c4bep1')
        cursor = db.cursor()
        sorted_keys = sorted(save_result.keys(), key=lambda x: tuple(map(int, x.split('-')[:2])))

        for key in sorted_keys:
            # print(key, value)
            # time = datetime.fromtimestamp(timestamp.timestamp())
            sql = "insert into link_stat(link_id,throughput,delay,jitter,loss) values('%s',%s,%s,%s,%s)" % (
                key, save_result[key]['throughput'], save_result[key]['delay'], save_result[key]['jitter'], save_result[key]['loss'])

            cursor.execute(sql)

        for key, value in self.discover.link_stat.items():
            src_dpid = key[0]
            dst_dpid = key[1]

            sql = "update link set link_throughput=%s,link_delay=%s,link_jitter=%s,link_loss=%s where src_dpid=%s and " \
                  "dst_dpid=%s" % (
                      value['throughput'], value['delay'], value['jitter'], value['loss'], src_dpid, dst_dpid)
            cursor.execute(sql)

        db.commit()
        cursor.close()
        db.close()

    def get_loss(self):
        temp = 0
        # print(self.packets_result)
        sw_num = len(get_switch(self, None)) * 0.5
        temp_packets = self.packets_result.copy()
        full_packet = setting.DELAY_DETECTING_PERIOD + 1 - sw_num * setting.DELAY_DETECTING_PERIOD / 10
        for key, value in self.discover.link_to_port.items():
            src = key[0]
            dst = key[1]
            src_port = value[0]
            dst_port = value[1]
            key1 = "%s-%s-%s-%s" % (src, src_port, dst_port, dst)
            key2 = "%s-%s-%s-%s" % (dst, dst_port, src_port, src)
            if key1 not in temp_packets or key2 not in temp_packets:
                self.loss_result[key1] = 0
                continue
            if temp_packets[key1] <= temp_packets[key2]:
                temp = temp_packets[key1]
            else:
                temp = temp_packets[key2]

            self.packets_result[key1] = 0

            if temp >= full_packet:
                self.loss_result[key1] = 0
            else:
                self.loss_result[key1] = float((full_packet - temp)) / full_packet * 100

        # print(self.loss)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):

        timestamp = time.time()
        try:
            latency = timestamp - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = latency
        except:
            return

    def get_delay(self, src, dst):
        try:
            t1 = self.discover.graph[src][dst]['linkdelay']
            t2 = self.discover.graph[dst][src]['linkdelay']
            t3 = self.echo_latency[src]
            t4 = self.echo_latency[dst]

            delay = (t1 + t2 - t3 - t4) / 2
            return max(delay, 0)
        except:
            return 0

    def _save_link_delay(self, src=0, dst=0, linkdelay=0):
        try:
            self.discover.graph[src][dst]['linkdelay'] = linkdelay
        except:
            if self.discover is None:
                self.discover = lookup_service_brick('discover')
            return

    def create_link_delay(self):

        try:
            for src in self.discover.graph:
                for dst in self.discover.graph[src]:
                    if src == dst:
                        self.discover.graph[src][dst]['delay'] = 0
                        continue
                    delay = self.get_delay(src, dst)

                    if (src, dst) in self.discover.link_to_port:
                        key1 = "%s-%s-%s-%s" % (
                            src, self.discover.link_to_port[(src, dst)][0], self.discover.link_to_port[(src, dst)][1],
                            dst)
                        if key1 in self.delay_result:
                            self.jitter_result[key1] = abs(delay * 1000 - self.delay_result[key1])
                        else:
                            self.jitter_result[key1] = 0
                        self.delay_result[key1] = delay * 1000

                    self.discover.graph[src][dst]['delay'] = delay
        except:
            if self.discover is None:
                self.discover = lookup_service_brick('discover')
            return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        try:
            src_dpid, src_outport = LLDPPacket.lldp_parse(msg.data)
            dst_dpid = msg.datapath.id
            dst_inport = msg.match['in_port']

            key = "%s-%s-%s-%s" % (src_dpid, src_outport, dst_inport, dst_dpid)
            if key not in self.packets_result:

                self.packets_result[key] = 0
            else:
                self.packets_result[key] += 1

            if self.sw_module is None:
                self.sw_module = lookup_service_brick('switches')

            for port in self.sw_module.ports.keys():
                if src_dpid == port.dpid and src_outport == port.port_no:
                    delay = self.sw_module.ports[port].delay
                    self._save_link_delay(src=src_dpid, dst=dst_dpid,
                                          linkdelay=delay)
        except LLDPPacket.LLDPUnknownFormat as e:
            return
