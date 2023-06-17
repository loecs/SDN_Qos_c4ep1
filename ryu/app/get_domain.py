from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, udp
from scapy.all import DNS, DNSQR

class DNSMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNSMonitor, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype==0x800:	    
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip.proto == 17:
            	udp_pkt = pkt.get_protocol(udp.udp)                
                if udp_pkt.dst_port == 53:    
                    text=str(pkt)                
                    pos_r=text.rfind('\'')
		    s=text[text.rfind('\'',0,pos_r)+1:pos_r]
		    #self.logger.info(s)  
		     
		    pos_l=s.find('\\x00\\x00\\x00\\x00\\x00\\x00')+24
		    
		    pos_r=len(s)
		    for i in range(1,6):
		        pos_r=s.rfind('\\',pos_l,pos_r)
		    s=s[pos_l:pos_r]+'\\'
		    #self.logger.info(s)
		    pos_l=0
		    domain=''
		    for i in range(0,s.count('\\')-1):
		    	if(s[pos_l+1]=='x'):
		    	    domain +=s[pos_l+4:s.find('\\',pos_l+1)]+'.'
		    	else:
		    	    domain +=s[pos_l+1:s.find('\\',pos_l+1)]+'.'
		    	pos_l=s.find('\\',pos_l+1)
		    domain=domain[:len(domain)-1]
		    self.logger.info(domain)	
		    
 					           

