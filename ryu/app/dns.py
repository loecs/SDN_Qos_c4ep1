from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import pymysql

db = pymysql.connect(host='cloud.loecs.com',
                     port=33060,
                     user='c4bep1',
                     password='c4bep1',
                     database='c4bep1')

cursor = db.cursor()


def dns_records(pkt):
    if pkt.haslayer(DNSRR):
        rcode = pkt[DNS].rcode 
        qname = pkt[DNSQR].qname
        if rcode == 0:
            for i in range(pkt[DNS].ancount):
                if pkt[DNS].an[i].type == 1:
                    new_domain = qname.decode('utf-8')[:len(qname.decode('utf-8'))-1]
                    new_ip = pkt[DNS].an[i].rdata
                    print(new_domain + " - " + new_ip)
                    #检查数据库中是否存在域名，不存在则添加
                    sql = "select * from domain where domain = '%s'" % new_domain
                    cursor.execute(sql)
                    result = cursor.fetchall()
                    if len(result) == 0:
                        sql = "insert into domain(domain) values('%s')" % new_domain
                        cursor.execute(sql)
                        db.commit()
                    #检查ipv4表中是否存在IP，不存在则添加IP和对应的域名
                    sql = "select * from ipv4 where ip = '%s'" % new_ip
                    cursor.execute(sql)
                    result = cursor.fetchall()
                    if len(result) == 0:
                        sql = "insert into ipv4(ip,domain) values('%s','%s')" % (new_ip,new_domain)
                        cursor.execute(sql)
                        db.commit()
                    else:
                    #获取ip对应的域名
                        sql = "select domain from ipv4 where ip = '%s'" % new_ip
                        cursor.execute(sql)
                        result = cursor.fetchall()
                        old_domain = result[0][0]
                        #判断该域名是否相同
                        if old_domain != new_domain:
                            #不同则更新域名
                            sql = "update ipv4 set domain = '%s' where ip = '%s'" % (new_domain,new_ip)
                            cursor.execute(sql)
                            db.commit()







sniff(filter="udp port 53", prn=dns_records)

