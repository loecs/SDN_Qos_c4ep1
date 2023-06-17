

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.mac import haddr_to_bin
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.controller import mac_to_port

import networkx as nx


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {} # maps the in_port to dpid-source mac
		self.port_to_switch = {} # dictionary storing ports active in on a switch in the spanning tree
		self.topology_api_app = self
		self.net=nx.DiGraph()  # a graph storing the original topology of the network
		self.span=nx.DiGraph() # the spanning tree which we've calculated
		self.nodes = {}  # a dictionary of all nodes
		self.links = {} # dictionary of all links in the network
		self.no_of_nodes = 0 # count
		self.no_of_links = 0
		self.i=0
		self.linksport = [] # list storing pairs of dpid and active ports on that switch.
		self.count = 0

	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):

		switch_list = get_switch(self.topology_api_app, None)
		switches=[switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		switch_to_port = {} # dictionary of switches and all their active ports.
		switch_list = [] # list of switches.

		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

		for x in links:
			switch_list.append(x[0])
			self.linksport.append([x[0],x[2]['port']])

		switch_list = list(set(switch_list))

		for sid in switch_list:
			if sid not in switch_to_port.keys():
				switch_to_port[sid] = []
			for dp_port in self.linksport:
				if(dp_port[0] == sid):
					switch_to_port[sid].append(dp_port[1])
					switch_to_port[sid] = list(set(switch_to_port[sid]))


		print(switch_to_port)
		print(switch_list)

		self.net.add_edges_from(links)

		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		for x in links:
			switch_list.append(x[0])
			self.linksport.append([x[0],x[2]['port']])

		switch_list = list(set(switch_list))

		for sid in switch_list:
			if sid not in switch_to_port.keys():
				switch_to_port[sid] = []
			for dp_port in self.linksport:
				if(dp_port[0] == sid):
					switch_to_port[sid].append(dp_port[1])
					switch_to_port[sid] = list(set(switch_to_port[sid]))
		print(switch_to_port)
		print(switch_list)





		########### Construction of spanning tree from the netwrok topology ##############################
		self.net.add_edges_from(links)
		my_links_list = []

		H = self.net.to_undirected()
		mst = nx.minimum_spanning_tree(H)
		self.span = mst.to_directed()
		print("Original topology: {}".format(self.net.edges()))
		print("Spanning tree: {}".format(self.span.edges()))

		###############Exraction of active ports on every switch in the spanning tree########################
		link_dict = {}    # maps each link to the input port connecting it.
		for link in links_list:
			link_dict[(link.src.dpid, link.dst.dpid)] = link.src.port_no
			self.no_of_links += 1
		print("link_dict before spanning tree: {}".format(link_dict))

		A = set(self.net.edges())
		B = set(self.span.edges())
		deleted_links =  A - B
		deleted_links = list(deleted_links)


		# delete the links in link_dict which are not part of spanning tree but of the original network.
		for link in deleted_links:
			del link_dict[link]

		print("link_dict after spanning tree: {}".format(link_dict))



		#link_dict keys are pairs: (source_dpid, dest_dpid)

		for link in link_dict.keys():
			self.port_to_switch[link[0]] = [1] # since port 1 is host on every switch, this might be a problem if a switch has more than 1 host.

		for link in link_dict.keys():
			self.port_to_switch[link[0]].append(link_dict[link])

		#port_to_switch has dpid as key, and value as a list with all the
		#active ports on the spanning tree
		#we selectively forward packet_in to only these ports
		print("List of active ports per switch: ", self.port_to_switch) #### this is all we needed guys  port_to_switch!!!!!!!

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)
		print(datapath)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return


		dst = eth.dst
		src = eth.src

		dpid = datapath.id
		print("dpid: ", dpid)

		self.mac_to_port.setdefault(dpid, {})
		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		# save a in_port to respecetive dpid-sourcemac mapping
		self.mac_to_port[dpid][src] = in_port
		####### if dst is in mac_to_port, we know the out_port, and just install flow rule which send the packet to that port on that switch#######################
		if dst in self.mac_to_port[dpid]:

			out_port = self.mac_to_port[dpid][dst]
			actions = [parser.OFPActionOutput(out_port)]
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
			self.add_flow(datapath, 1, match, actions)

			if msg.buffer_id == ofproto.OFP_NO_BUFFER:
				data = msg.data


			## packet out##########
			out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)


			datapath.send_msg(out)

		############ to know the out port, we have actions for sending the packet_in to all the active ports in the spanning tree we created###############
		############# we don't flood anymore, so no braodcast storm in a loopy topology####################################################################

		else:

			actions = [] # list to store the actions

			for x in self.port_to_switch[dpid]:
				out_port = x
				actions.append(parser.OFPActionOutput(out_port)) ## choosing each port on the switch as out_port and saving it in the actions list

			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)    ##match condition
			self.add_flow(datapath, 1, match, actions) # adding the flow where matching condition is satisfied by the actions

			if msg.buffer_id == ofproto.OFP_NO_BUFFER:
				data = msg.data

			### packet_out########
			out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								in_port=in_port, actions=actions, data=data)
			datapath.send_msg(out)








