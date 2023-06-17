from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.topology.api import get_switch, get_link, get_host
import pymysql
import time


class SimpleMonitor(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.rx_b = {}
        self.throughput = {}
        self.throughput_result = {}
        self.loss = {}
        self.packet = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):

        while True:
            '''
            links=get_link(self)
            for link in links:
                self.logger.info(link)
            '''
            for dp in self.datapaths.values():
                if dp.id not in self.rx_b:
                    self.rx_b[dp.id] = {}
                    self.throughput[dp.id] = {}
                self._request_stats(dp)
            self.get_throughput()
            hub.sleep(5)

    def get_throughput(self):

        links = []
        links = get_link(self)
        for link in links:
            # self.logger.info(link)
            if not self.throughput[link.src.dpid]:
                return
            if link.src.dpid < link.dst.dpid:
                if link.src.dpid in self.throughput and link.src.port_no in self.throughput[link.src.dpid]:
                    key = "%s-%s-%s-%s" % (link.src.dpid, link.src.port_no, link.dst.port_no, link.dst.dpid)
                    self.throughput_result[key] = self.throughput[link.src.dpid][link.src.port_no]
                    if self.packet[link.dst.dpid]['tx_packets'] == 0:
                        self.loss[key] = 0
                    else:
                        self.loss[key] = (self.packet[link.src.dpid]['tx_packets'] - self.packet[link.dst.dpid]['rx_packets']) / self.packet[link.src.dpid]['tx_packets'] * 100

        #self.logger.info(self.throughput_result)
        #self.logger.info(self.loss)

    def _request_stats(self, datapath):
        # self.logger.info('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        '''
        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

        '''

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        ''''''
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')

        for stat in sorted(body, key=attrgetter('port_no')):
            if stat.port_no not in self.rx_b[ev.msg.datapath.id]:
                self.rx_b[ev.msg.datapath.id][stat.port_no] = 0
                self.throughput[ev.msg.datapath.id][stat.port_no] = 0
            else:
                self.throughput[ev.msg.datapath.id][stat.port_no] = (stat.rx_bytes - self.rx_b[ev.msg.datapath.id][
                    stat.port_no]) * 8 / 10
                self.rx_b[ev.msg.datapath.id][stat.port_no] = stat.rx_bytes
                # self.logger.info(self.rx_b[ev.msg.datapath.id][stat.port_no])
                # self.logger.info(self.throughput)
            self.packet[ev.msg.datapath.id] = {'rx_packets': stat.rx_packets, 'tx_packets': stat.tx_packets}
            ''''''
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

