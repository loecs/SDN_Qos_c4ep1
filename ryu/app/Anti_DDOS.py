from ryu.app import setting
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types
import shortest_forwarding
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.metrics import precision_score
from sklearn.metrics import accuracy_score
from sklearn.metrics import f1_score
import pymysql
import time
import setting


class AntiDDos(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):

        super(AntiDDos, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = time.time()

        self.flow_training()
        self.discover = lookup_service_brick('discover')
        end = time.time()
        print("Training time: ", (end - start))
        if setting.SAVE_SQL:
            self.db = pymysql.connect(host='192.168.50.133',
                                      port=3306,
                                      user='c4bep1',
                                      password='c4bep1',
                                      database='c4bep1')

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:

            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)
            self.flow_predict()
            '''
            temp_ban_ip = self.ban_ip.copy()
            for key, value in temp_ban_ip.items():
                timestamp = datetime.now()
                timestamp = timestamp.timestamp()
                if timestamp - value['timestamp'] > 20:
                    # print("unban")
                    del self.ban_ip[key]

            '''

    def _request_stats(self, datapath):

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = time.time()

        file0 = open("PredictFlowStatsfile.csv", "w")
        file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
                    'flow_duration_sec,flow_duration_nsec,packet_count,byte_count,'
                    'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if flow.priority == 1 and 'ip_proto' in flow.match],
                           key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'],
                                             flow.match['ip_proto'])):

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']

            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']

            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

            try:
                packet_count_per_second = stat.packet_count / stat.duration_sec
                packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0

            try:
                byte_count_per_second = stat.byte_count / stat.duration_sec
                byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0

            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                                stat.match['ip_proto'], icmp_code, icmp_type,
                                stat.duration_sec, stat.duration_nsec,
                                stat.packet_count, stat.byte_count,
                                packet_count_per_second, packet_count_per_nsecond,
                                byte_count_per_second, byte_count_per_nsecond))

        file0.close()

    def flow_training(self):

        self.logger.info("Flow Training ...")

        flow_dataset = pd.read_csv('FlowStatsfile.csv')

        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

        X_flow = flow_dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')

        y_flow = flow_dataset.iloc[:, -1].values

        X_train, X_test, y_train, y_test = train_test_split(X_flow, y_flow, test_size=0.25,
                                                            random_state=0)

        # classifier = DecisionTreeClassifier(criterion='entropy', random_state=0)
        classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
        self.flow_model = classifier.fit(X_train, y_train)

        y_pred = self.flow_model.predict(X_test)

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
            src_ip = predict_flow_dataset.iloc[:, 3].copy().values
            dst_ip = predict_flow_dataset.iloc[:, 5].copy().values
            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')

            y_pred = self.flow_model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0

            for i in y_pred:

                if i == 0:

                    legitimate_trafic = legitimate_trafic + 1
                else:
                    # print(predict_flow_dataset.iloc[i,:])
                    ddos_trafic = ddos_trafic + 1
                    # bug!!!!!!!!!!
                    victim = src_ip[i]
                    attacker = dst_ip[i]

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_trafic / len(y_pred) * 100) > 70:
                self.logger.info("normal")
            else:
                self.logger.info("error")
                self.logger.info("victim: {}".format(victim))
                self.logger.info("attacker: {}".format(attacker))

                self.defense(attacker, victim)

            self.logger.info("------------------------------------------------------------------------------")

            file0 = open("PredictFlowStatsfile.csv", "w")

            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
                        'flow_duration_sec,flow_duration_nsec,packet_count,'
                        'byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,'
                        'byte_count_per_nsecond\n')
            file0.close()

        except:
            pass

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # print(datapath.id)
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle, hard_timeout=hard,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def defense(self, attacker_ip, victim_ip):

        src_switch = None
        src_port = None
        dst_switch = None

        for key, value in self.discover.access_table.items():
            if value[0] == attacker_ip:
                src_switch = key[0]
                src_port = key[1]
            if value[0] == victim_ip:
                dst_switch = key[0]
            if src_switch is not None and dst_switch is not None:
                break

        paths = self.discover.shortest_paths.get(src_switch).get(dst_switch)[0]

        actions = []
        datapath = self.datapaths[src_switch]
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=src_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=victim_ip)
        self._add_flow(datapath, 100, match, actions, idle=40, hard=0)
        match = parser.OFPMatch(in_port=src_port, eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=victim_ip)
        self._add_flow(datapath, 100, match, actions, idle=40, hard=0)

        # timestamp = datetime.now()
        # timestamp = timestamp.timestamp()
        # self.ban_ip[victim_ip] = {'timestamp': timestamp, 'ban_switch': src_switch, 'ban_port': src_port}

        paths = str(paths)
        paths = paths.replace('[', '')
        paths = paths.replace(']', '')
        paths = paths.replace(' ', '')
        if setting.SAVE_SQL:
            self.save_sql(paths, victim_ip)

    def save_sql(self, paths, victim_ip):
        cursor = self.db.cursor()
        sql = "insert into abnormal_traffic(paths,victim_ip) values('%s','%s')" % (
            paths, victim_ip)
        cursor.execute(sql)
        self.db.commit()
        cursor.close()
