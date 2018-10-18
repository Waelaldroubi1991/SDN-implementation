# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# NWEN 302 - Lab3: SDN
# Student Name: Tianfu Yuan
# Student ID: 300228072
# Username: yuantian

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct
import time

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

""" My Code Begin """
from ryu.lib.mac import haddr_to_str
from ryu.lib.ip import *                           # import ip library (task 1)
from ryu.lib.ofctl_v1_0 import get_flow_stats      # for count traffic (task 2)
from ryu.topology import event, switches           # topology discovey (task 3)
from ryu.topology.api import get_switch, get_link  # topology discovey (task 3)
from ryu.lib.packet import lldp                    # import lldp packet (task 3)
from ryu.ofproto.ether import ETH_TYPE_LLDP        # import lldp library (task 3)
""" My Code End """

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    """ My Code Begin """
    # set up traffic counter to count all the traffic
    #traffic_counter = 0
    """ My Code End """
    
    """ My Code Begin """
    # predefined IP address and MAC address for h1, h2 & h3
    ipv4_host1 = '10.0.0.1';
    ipv4_host2 = '10.0.0.2';
    ipv4_host3 = '10.0.0.3';
    ipv4_uint32_host1 = 167772161
    ipv4_uint32_host2 = 167772162
    ipv4_uint32_host3 = 167772163
    mac_host1 = haddr_to_bin('00:00:00:00:00:01')
    mac_host2 = haddr_to_bin('00:00:00:00:00:02')
    mac_host3 = haddr_to_bin('00:00:00:00:00:03')
    """ My Code End """

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        """ My Code Begin """
        self.isInitialize = False
        self.portHost1 = -1;
        self.portHost2 = -1;
        self.portHost3 = -1;
        self.stats = []
        """ My Code End """

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        
        """ My Code Begin """
        # add wildcards
        # The following code was based on Ryu offical code
        # Link: https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_stp.py
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST
        """ My Code End """

        """ 
        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))
        """
        
        """ My Code Begin """
        match = datapath.ofproto_parser.OFPMatch(wildcards, in_port, 0, dst, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        # set hard time to 60, so that the rules expire periodically and trigger flow-deletion messages that contain the counter values for the expired rules.
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=60,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        """ My Code End """
        
        """ 
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        """
        
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        """
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        """
        
        dpid = datapath.id
        
        """ My Code Begin """
        # unpack using '6s6sH' to have the packet in certain format
        # The following code was based on Ryu offical code
        # Link: https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_stp.py
        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        
        # get the port number of host 1 via MAC address
        if (self.portHost1 == -1 and src == SimpleSwitch.mac_host1):
            self.portHost1 = msg.in_port
        
        # send stats request to switch if host 1 receievd a packet
        if (not self.isInitialize and self.portHost1 != -1):
            self.isInitialize = True
            self._port_status_request(datapath)
        """ My Code End """


        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        """ My Code Begin """
        # block IPv4 traffic between host 2 and host 3
        if (self._block_packet(msg.data)):
            actions = []
            self._block_flow(datapath, SimpleSwitch.ipv4_uint32_host2, SimpleSwitch.ipv4_uint32_host3)
        else:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, msg.in_port, dst, actions)
        """ My Code End """
        
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)
    
    
    """ My Code Begin """
    # if the flow is between host 2 and host 3 -> true; otherwise, set to false.
    def _block_packet(self, data):
        data_packet = packet.Packet(data)
        for protocol in data_packet.protocols:
            if (protocol.protocol_name == 'ipv4' and ((ipv4_to_str(protocol.src) == SimpleSwitch.ipv4_host2 and ipv4_to_str(protocol.dst) == SimpleSwitch.ipv4_host3) or (ipv4_to_str(protocol.src) == SimpleSwitch.ipv4_host3 and ipv4_to_str(protocol.dst) == SimpleSwitch.ipv4_host2))):
                return True
        return False
    
    # block flow between host 2 and host 3 as required
    def _block_flow(self, datapath, ip1, ip2):
        matches = []
        ofproto = datapath.ofproto
        
        # response to table stats - wildcards (32 bits), which contains all the masks for fields in match structure
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~(ofproto_v1_0.OFPFW_NW_SRC_ALL | ofproto_v1_0.OFPFW_NW_DST_ALL)
        
        matches.append(datapath.ofproto_parser.OFPMatch(
                       wildcards, 0, 0, 0, 0, 0, 0, 0, 0, ip1, ip2, 0, 0))
        matches.append(datapath.ofproto_parser.OFPMatch(
                       wildcards, 0, 0, 0, 0, 0, 0, 0, 0, ip2, ip1, 0, 0))
    
        # set up a rule with the hard time, and then send the request to the switch
        for match in matches:
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=10,
                priority=ofproto.OFP_DEFAULT_PRIORITY,
                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=[])
            datapath.send_msg(mod)
    """ My Code End """
    
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
            """ My Code Begin """
            if (port_no == self.portHost1):
                self.logger.info('Host #1 Tx\Rx statistics - %s', self.stats)
            """ My Code End """
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    """ My Code Begin """
    # The following code was based on Traffic Monitor example code on Ryu Book.
    # Link: https://osrg.github.io/ryu-book/en/html/traffic_monitor.html
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_status_reply_handler(self, ev):
        body = ev.msg.body
        self.stats = []
        
        for stat in body:
            self.stats.append('port_no = %d , Tx_packets = %d , Rx_packets = %d' % (stat.port_no, stat.rx_packets, stat.tx_packets))
        
        # send port status request every 1 second
        time.sleep(1)
        self._port_status_request(ev.msg.datapath)
    
    """
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
    """

    # send port request
    def _port_status_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, self.portHost1)
        datapath.send_msg(req) 
    """ My Code End """
    
    """ My Code Begin """
    # topology discovery
    # The following code was based on following websites
    # Link: http://sdn-lab.com/2014/12/31/topology-discovery-with-ryu/
    #       http://sdn-lab.com/2014/12/25/shortest-path-forwarding-with-openflow-on-ryu/
    """@set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
    """
    """ My Code End """

""" My Code Begin """
# add LLDP database (imcompleted)
"""class lldp(object):
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        pkt = packet.Packet()
        
        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = dl_addr
        ethertype = ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)
"""
""" My Code End """
