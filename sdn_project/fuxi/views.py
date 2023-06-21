import requests
from django.shortcuts import render
from django.views import View
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.db import models
from fuxi.models import link, host_switch, abnormal_traffic, link_stat
import json
import ast
import re


def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == 'admin' and password == 'admin':
            return render(request, 'index.html')
        else:
            return HttpResponse('用户名或密码错误')
    return render(request,'page-login.html')


def index(request):
    # 从数据库中先获取链路信息，将链路信息的源交换机id、源端口、目的交换机id、目的端口存储在link_list中
    link_status = list(link.objects.all().values())
    link_list = []
    for link_status_item in link_status:
        link_list.append([link_status_item['src_dpid'], link_status_item['src_port'], link_status_item['dst_dpid'], link_status_item['dst_port']])
    # print(link_list)

    # 从数据库中获取主机与交换机之间的连接信息，将主机ip、主机mac、交换机id、交换机端口存储在host_switch_list中
    host_switch_status = list(host_switch.objects.all().values())
    host_switch_list = []
    for host_switch_status_item in host_switch_status:
        host_switch_list.append([host_switch_status_item['host_ip'], host_switch_status_item['host_mac'], host_switch_status_item['switch_dpid'], host_switch_status_item['switch_port']])
    # print(host_switch_list)

    # 先为交换机创建nodes节点和edges边，然后转成json格式
    nodes = []
    edges = []
    # 为交换机创建nodes节点，判断交换机是否已经在nodes中，如果不在则添加，如果在则不添加，并记录交换机之间的连接关系
    for link_item in link_list:
        if link_item[0] not in nodes:
            nodes.append(link_item[0])
        if link_item[2] not in nodes:
            nodes.append(link_item[2])
        edges.append({'from': link_item[0], 'to': link_item[2]})
    nodes = [{'id': id, 'label': 'ovs'+str(id)} for id in nodes]
    # print(nodes)
    # print(edges)
    # 为主机创建nodes节点，判断主机是否已经在nodes中，如果不在则添加，如果在则不添加，并记录主机与交换机之间的连接关系
    id = len(nodes)+1
    for host_switch_item in host_switch_list:
        nodes.append({'id': id, 'label': host_switch_item[0]})
        edges.append({'from': host_switch_item[2], 'to': id})
        id += 1
    # 将nodes和edges放在一个字典中，转成json格式，写入json文件中
    graph = {'nodes': nodes, 'edges': edges}
    # print(graph)
    with open('fuxi/static/show-data/graph.json', 'w') as f:
        f.write(json.dumps(graph))
    # add_meter_table_data(request)
    return render(request,'index.html')

def link_info(request):
    # 从数据库中获取链路信息，（吞吐量、时延、抖动、丢包率）
    link_status = list(link_stat.objects.all().values())
    # 处理时间格式
    for link_status_item in link_status:
        link_status_item['record_time'] = link_status_item['record_time'].strftime('%Y-%m-%d %H:%M:%S')
    # print(link_status)

    # 将链路信息转换成layui表格所需的格式
    link_json = {}
    link_json['code'] = 0
    link_json['msg'] = ''
    link_json['count'] = len(link_status)
    link_json['data'] = link_status

    # 将link_json转成json格式写入json文件中
    with open('fuxi/static/show-data/link-data.json', 'w') as f:
        f.write(json.dumps(link_json))
    return render(request,'link-info.html')

def modify_bandwidth(request):
    return HttpResponse('ok')

def endpoint_list(request):
    # 从数据库中获取主机与交换机之间的连接信息，将主机ip、主机mac、交换机id、交换机端口存储在host_switch_list中
    host_switch_status = list(host_switch.objects.all().values())
    host_switch_list = []
    for host_switch_status_item in host_switch_status:
        temp = {'id':host_switch_status_item['id'],'ip': host_switch_status_item['host_ip'], 'mac': host_switch_status_item['host_mac'], 'switch_dpid': host_switch_status_item['switch_dpid'], 'switch_port': host_switch_status_item['switch_port']}
        host_switch_list.append(temp)
    # 将host_switch_list转成json格式写入json文件中
    with open('fuxi/static/show-data/endpoint-list-data.json', 'w') as f:
        f.write(json.dumps(host_switch_list))
    return render(request,'endpoint-list.html')

def unusual_traffic(request):
    # 从数据库中获取异常流量数据
    abnormal_traffic_list = list(abnormal_traffic.objects.all().values())
    # 处理时间格式
    for abnormal_traffic_item in abnormal_traffic_list:
        abnormal_traffic_item['intrusion_time'] = abnormal_traffic_item['intrusion_time'].strftime('%Y-%m-%d %H:%M:%S')
    print(abnormal_traffic_list)
    # 将异常流量数据转成json格式存到json文件中
    data = {}
    data['code'] = 0
    data['msg'] = ''
    data['count'] = len(abnormal_traffic_list)
    data['data'] = abnormal_traffic_list
    with open('fuxi/static/show-data/flow-table-data.json', 'w') as f:
        f.write(json.dumps(data))
    return render(request,'unusual-traffic.html')

def flow_table(request):
    # 调用rest api获取交换机id
    dpid_list = []
    flow_table_list = []
    url = "http://cloud.loecs.com:7070/stats/switches"
    response = requests.get(url)
    # 获取交换机id存储在dpip_list中
    if response.status_code == 200:
        dpid_list = response.text
    # 调用rest api获取流表信息存储在flow_table_list中
    dpid_list = eval(dpid_list)
    for dpid in dpid_list:
        url = "http://cloud.loecs.com:7070/stats/flow/" + str(dpid)
        response = requests.get(url)
        if response.status_code == 200:
            # 将response.text转换为json格式,并添加到flow_table_list中
            # print(response.text)
            flow_table_list.append(json.loads(response.text))  # 字典格式存储
    print(flow_table_list)

    # 将flow_table_list转成json格式写入json文件中
    with open('fuxi/static/show-data/flow-table-data.json', 'w') as f:
        f.write(json.dumps(flow_table_list))
    return render(request,'flow-table.html')

def meter_table(request):
    # 调用rest api获取交换机id
    dpid_list = []
    link_status = list(link.objects.all().values())
    link_list = []
    for link_status_item in link_status:
        link_list.append([link_status_item['src_dpid'], link_status_item['src_port'], link_status_item['dst_dpid'], link_status_item['dst_port']])
    # print(link_list)
    for i in link_list:
        # 如果交换机id不在dpid_list中，则添加，如果在则不添加
        if i[0] not in dpid_list:
            dpid_list.append(i[0])
        if i[2] not in dpid_list:
            dpid_list.append(i[2])
    # print(dpid_list)
    # 调用rest api获取meter表信息
    meter_table_list =[]
    for dpid in dpid_list:
        url = "http://cloud.loecs.com:7070/stats/meter/" + str(dpid)
        response = requests.get(url)
        if response.status_code == 200:
            # 将response.text转换为json格式,并添加到meter_table_list中
            # print(response.text)
            # temp = json.loads(response.text)['dpid']
            # if temp == None:
            #     continue
            meter_table_list.append(json.loads(response.text))  # 字典格式存储
    # print(meter_table_list)
    switch_dpid = []
    for item in meter_table_list:
        for key in item:
            value = item[key]
            temp = {}
            if value:
                temp['dpid'] = key
                temp['meter_id'] = value[0]['meter_id']
                temp['flow_count'] = value[0]['flow_count']
                temp['duration_sec']= value[0]['duration_sec']
                switch_dpid.append(temp)
            else:
                continue
    # print(switch_dpid)
    # 将switch_dpid转成json格式写入json文件中
    with open('fuxi/static/show-data/meter-table-data.json', 'w') as f:
        f.write(json.dumps(switch_dpid))
    return render(request,'meter-table.html')

def delete_flow_table(request):
    data = request.body.decode('utf-8')
    if data == '':
        return HttpResponse('fail')
    data = json.loads(data)
    string = str(data['actions'][0])
    # 写正则表达式，将actions_data中以:分割的两个字段提取出来
    result = re.match(r'([^:]+):(.+)', string)
    # 将数据重新构造成rest api所需的格式
    data['actions'] = [{'type': result.group(1), 'port': result.group(2)}]
    # 将数据转成json格式
    data = json.dumps(data)
    print(data)
    # 调用rest api删除流表
    url = "http://cloud.loecs.com:7070/stats/flowentry/delete"
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return HttpResponse('ok')
    return HttpResponse('fail')


def add_flow_table(request):
    # 获取提交要添加的数据
    data = request.body.decode('utf-8')
    data = json.loads(data)
    # 重构actions字段
    string = data['data']['actions']
    result = re.match(r'([^:]+):(.+)', string)
    data['data']['actions'] = [{'type': result.group(1), 'port': result.group(2)}]
    # 处理match字段
    temp = data['data']['match']
    data['data']['match'] = json.loads(temp)
    item = json.dumps(data['data'])
    print(item)
    url = "http://cloud.loecs.com:7070/stats/flowentry/add"
    response = requests.post(url, data=item)
    if response.status_code == 200:
        return HttpResponse('ok')
    return HttpResponse('fail')

def add_meter_table(request):
    # 获取提交要添加的数据
    data = json.loads(request.body.decode('utf-8'))
    # 发送API请求
    # print(data)
    temp = data['data']
    data = {
        "dpid": temp['dpid'],
        "flags": [temp['flags']],
        "meter_id": temp['meter_id'],
        "bands": [
            {
                "type": temp['type'],
                "rate": temp['rate'],
            }
        ]
    }
    data=json.dumps(data)
    url = 'http://cloud.loecs.com:7070/stats/meterentry/add'
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return HttpResponse('ok')
    return HttpResponse('fail')

def delete_meter_table(request):
    data = request.body.decode('utf-8')
    data = json.loads(data)
    data = {
        "dpid": data['dpid'],
        "meter_id": data['meter_id']
    }
    data = json.dumps(data)
    url = 'http://cloud.loecs.com:7070/stats/meterentry/delete'
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return HttpResponse('ok')
    return HttpResponse('fail')
