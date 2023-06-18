#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
from mininet.topo import Topo

class MyTopo( Topo ):

    def build( self ):

        
        info( '*** Add switches\n')
        s7 = self.addSwitch('s7', cls=OVSKernelSwitch)
        s8 = self.addSwitch('s8', cls=OVSKernelSwitch)
        s12 = self.addSwitch('s12', cls=OVSKernelSwitch)
        s5 = self.addSwitch('s5', cls=OVSKernelSwitch)
        s10 = self.addSwitch('s10', cls=OVSKernelSwitch)
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch)
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
        s11 = self.addSwitch('s11', cls=OVSKernelSwitch)
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
        s9 = self.addSwitch('s9', cls=OVSKernelSwitch)
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch)
        s6 = self.addSwitch('s6', cls=OVSKernelSwitch)
        s13 = self.addSwitch('s13', cls=OVSKernelSwitch)
        s14 = self.addSwitch('s14', cls=OVSKernelSwitch)
 

        info( '*** Add hosts\n')
        h=[]
        for i in range(1,15):
            h.append(self.addHost(('h'+str(i)), cls=Host, ip=('10.0.0.'+str(i)), defaultRoute=None))

        info( '*** Add links\n')
        self.addLink(s2, s1,cls=TCLink,bw=100)
        self.addLink(s1, s3,cls=TCLink,bw=100,delay='2s')
        self.addLink(s3, s2,cls=TCLink,bw=100)
        self.addLink(s1, s4,cls=TCLink,bw=100)
        self.addLink(s4, s5,cls=TCLink,bw=100,delay='10ms', jitter='500ms')
        self.addLink(s5, s6,cls=TCLink,bw=100)
        self.addLink(s6, s3,cls=TCLink,bw=100)
        self.addLink(s5, s7,cls=TCLink,bw=100)
        self.addLink(s7, s8,cls=TCLink,bw=100)
        self.addLink(s2, s8,cls=TCLink,bw=100,loss=60)
        self.addLink(s9, s4,cls=TCLink,bw=100)
        self.addLink(s9, s10,cls=TCLink,bw=100)
        self.addLink(s8, s11,cls=TCLink,bw=100)
        self.addLink(s11, s10,cls=TCLink,bw=100)
        self.addLink(s9, s12,cls=TCLink,bw=100)
        self.addLink(s12, s11,cls=TCLink,bw=100)
        self.addLink(s6, s14,cls=TCLink,bw=100)
        self.addLink(s14, s11,cls=TCLink,bw=100)
        self.addLink(s12, s13,cls=TCLink,bw=100)
        self.addLink(s13, s10,cls=TCLink,bw=100)
        self.addLink(s13, s6,cls=TCLink,bw=100)
        self.addLink(s1, h[0])
        self.addLink(s2, h[1])
        self.addLink(s3, h[2])
        self.addLink(s4, h[3])
        self.addLink(s5, h[4])
        self.addLink(s6, h[5])
        self.addLink(s7, h[6])
        self.addLink(s8, h[7])
        self.addLink(s9, h[8])
        self.addLink(s10, h[9])
        self.addLink(s11, h[10])
        self.addLink(s12, h[11])
        self.addLink(s13, h[12])
        self.addLink(s14, h[13])
        
  
       

topos = { 'mytopo': ( lambda: MyTopo() ) }

