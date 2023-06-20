from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib.packet import packet, ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.app.rest_topology import TopologyController
from ryu.base.app_manager import lookup_service_brick
from ryu.lib import hub

import pymysql


class TopoDiscovery(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopoDiscovery, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.hosts = []
        self.discover = lookup_service_brick('discover')
        self.monitor_thread = hub.spawn(self._monitor)


    def _get_link_info(self,cursor,db):
        links = get_link(self)       
        for link in links:
            '''
            print('src_switch:', link.src.dpid, 'src_port:', link.src.port_no, 'dst_port:', link.dst.port_no,
            'dst_switch:', link.dst.dpid)
            '''
            sql = "SELECT * FROM link WHERE src_dpid = '%s' AND src_port = '%s' AND dst_port = '%s' AND dst_dpid = '%s'" % \
                    (link.src.dpid, link.src.port_no, link.dst.port_no, link.dst.dpid)
            try:
                
                cursor.execute(sql)
                
                results = cursor.fetchall()
                
                if len(results) == 0:
                    sql = "SELECT * FROM link WHERE src_dpid = '%s' AND src_port = '%s' AND dst_port = '%s' AND dst_dpid = '%s'" % \
                            (link.dst.dpid, link.dst.port_no, link.src.port_no, link.src.dpid)
                    cursor.execute(sql)
                    results = cursor.fetchall()
                   # print('no link ')
                    if len(results) == 0:
                        sql = "INSERT INTO link(src_dpid, src_port, dst_port, dst_dpid) VALUES ('%s', '%s', '%s', '%s')" % \
                                (link.src.dpid, link.src.port_no, link.dst.port_no, link.dst.dpid)
                        cursor.execute(sql)
                        db.commit()
                        #print("Because the database not have link info,Insert link Successful!")
                    else:
                        continue
                elif len(results) == 1:
                    sql = "UPDATE link SET link_status = '%s' WHERE src_dpid = '%s' AND src_port = '%s' AND dst_port = '%s' AND dst_dpid = '%s'" % \
                            ('up', link.src.dpid, link.src.port_no, link.dst.port_no, link.dst.dpid)
                    cursor.execute(sql)
                    db.commit()
                    #print("Because the database have link info,Update link Successful!")
            except:
                db.rollback()
               # print("Error: unable to fetch data")

    def _get_host_switch_info(self):
        host_switch_info = []
        for key, value in self.discover.access_table.items():
            #print(key,value)
            host_switch_info.append({
                'switch_dpid': key[0],
                'switch_port': key[1],
                'host_ip': value[0],
                'host_mac': value[1]
            })
        self.hosts = host_switch_info
        # print(self.hosts)
        return self.hosts

    def _save_host_switch_info(self,cursor,db):
        for host in self.hosts:
            sql = "SELECT * FROM host_switch WHERE host_ip = '%s'" % (host['host_ip'])
            # print(host)
            try:
                cursor.execute(sql)
                results = cursor.fetchall()

                if len(results) == 0:
                    sql = "INSERT INTO host_switch(switch_dpid, switch_port, host_ip, host_mac) VALUES ('%s', '%s', '%s', '%s')" % \
                          (host['switch_dpid'], host['switch_port'], host['host_ip'], host['host_mac'])
                    cursor.execute(sql)
                    db.commit()
                    print("Because the database not have host info,Insert host Successful!")
                elif len(results) == 1:
                    sql = "UPDATE host_switch SET switch_dpid = '%s', switch_port = '%s', host_ip = '%s', host_mac = '%s' WHERE host_ip = '%s'" % \
                          (host['switch_dpid'], host['switch_port'], host['host_ip'], host['host_mac'], host['host_ip'])
                    cursor.execute(sql)
                    db.commit()
                    # print("Because the database have host info,Update host Successful!")
            except:
                db.rollback()

    def _monitor(self):
        db = pymysql.connect(host='cloud.loecs.com',
                                     port=33060,
                                     user='c4bep1',
                                     password='c4bep1',
                                     database='c4bep1')
        cursor = db.cursor()
        sql = 'TRUNCATE TABLE link'
        cursor.execute(sql)                
        sql = 'TRUNCATE TABLE host_switch'
        cursor.execute(sql)
        db.commit()  
        while True:                      
            try:             
                print('The link table is reset')
                print('The host_switch table is reset')
                self._get_link_info(cursor, db)
                self._get_host_switch_info()
                self._save_host_switch_info(cursor, db)                

            except:
                print("Error occurred during monitoring")            
            hub.sleep(15)


