from django.db import models

# Create your models here.


# 交换机之间的链路表
class link(models.Model):
    id = models.AutoField(primary_key=True)
    src_dpid = models.IntegerField()
    src_port = models.IntegerField()
    dst_port = models.IntegerField()
    dst_dpid = models.IntegerField()
    link_status = models.CharField(max_length=12, default='up')
    link_bandwidth = models.IntegerField(default=100)
    class Meta:
        unique_together = ['src_dpid', 'src_port', 'dst_port', 'dst_dpid']
        db_table = 'link'


# 主机与交换机之间的连接信息
class host_switch(models.Model):
    id = models.AutoField(primary_key=True)
    host_ip = models.CharField(max_length=50)
    host_mac = models.CharField(max_length=50)
    switch_dpid = models.IntegerField()
    switch_port = models.IntegerField()
    class Meta:
        db_table = 'host_switch'


class abnormal_traffic(models.Model):
    id = models.AutoField(primary_key=True)
    intrusion_time = models.DateTimeField()
    paths = models.CharField(max_length=255)
    victim_ip = models.CharField(max_length=255)
    class Meta:
        db_table = 'abnormal_traffic'

class link_stat(models.Model):
    id = models.AutoField(primary_key=True)
    record_time = models.DateTimeField()
    link_id = models.CharField(max_length=255)
    throughput = models.IntegerField()
    delay = models.DecimalField(max_digits=16, decimal_places=12)
    jitter = models.DecimalField(max_digits=16, decimal_places=12)
    loss = models.DecimalField(max_digits=16, decimal_places=12)
    class Meta:
        db_table = 'link_stat'