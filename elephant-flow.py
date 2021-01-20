# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet, packet, arp, ipv4, tcp, udp
from ryu.lib import hub
import time
import random


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.current_route = 2
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)
        self.flow_ask = True
        self.routes = [1,2,3]
        self.flowid = 0
        self.h1ip = "10.0.0.1"
        self.h2ip = "10.0.0.2"
        self.current_priority = 2000
        self.allow = True
        self.flow_added = False
        self.flow_in = False
        self.flow_out = False
        self.elephant_treshold = 150000
        self.new_route_timeout = 40



    def route1(self,dpid_id,in_port):
        out_port = None
        if dpid_id == 1 and in_port == 1:
            out_port = 2
        elif dpid_id == 1 and in_port == 2:
            out_port = 1
        elif dpid_id == 2 and in_port == 1:
            out_port = 2
        elif dpid_id == 2 and in_port == 2:
            out_port = 1
        elif dpid_id == 5 and in_port == 2:
            out_port = 1
        elif dpid_id == 5 and in_port == 1:
            out_port = 2
        else:
            print("Any of that !!!!!!!!!!!!!!!!!!!!!!!")
        return out_port
    
    def route2(self,dpid_id,in_port):
        out_port = None
        if dpid_id == 1 and in_port == 1:
            out_port = 3
        elif dpid_id == 1 and in_port == 3:
            out_port = 1
        elif dpid_id == 3 and in_port == 1:
            out_port = 2
        elif dpid_id == 3 and in_port == 2:
            out_port = 1
        elif dpid_id == 5 and in_port == 3:
            out_port = 1
        elif dpid_id == 5 and in_port == 1:
            out_port = 3
        else:
            print("Any of that !!!!!!!!!!!!!!!!!!!!!!!")
        return out_port

    def route3(self,dpid_id,in_port):
        out_port = None
        if dpid_id == 1 and in_port == 1:
            out_port = 4
        elif dpid_id == 1 and in_port == 4:
            out_port = 1
        elif dpid_id == 4 and in_port == 1:
            out_port = 2
        elif dpid_id == 4 and in_port == 2:
            out_port = 1
        elif dpid_id == 5 and in_port == 4:
            out_port = 1
        elif dpid_id == 5 and in_port == 1:
            out_port = 4
        else:
            print("Any of that !!!!!!!!!!!!!!!!!!!!!!!")
        return out_port

    def monitor(self):
        self.logger.info("start flow monitoring thread")
        
        while True:
            hub.sleep(20)
            #for datapath in self.datapaths.values():
            if len(self.datapaths.values()) > 0:
                datapath = self.datapaths[1]
                ofp = datapath.ofproto
                #print(dir(datapath))
                ofp_parser = datapath.ofproto_parser
                req = ofp_parser.OFPFlowStatsRequest(datapath,1,ofp.OFPTT_ALL,ofp.OFPP_ANY, ofp.OFPG_ANY)
                datapath.send_msg(req)
                self.flow_id = datapath.id



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print("called")
        #print("Datapath : {}".format(dir(datapath)))

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.datapaths[int(datapath.id)] = datapath

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply,], MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        datapath_id = ev.msg.datapath.id
        print("Gather STATS !!!!!!!!!!!!!!!!!!!!!")
        for stat in ev.msg.body:
            #self.logger.info("Flow details:  %s ",stat.match)
            #self.logger.info("Match: {}".format(dir(stat.match._flow)))
            #self.logger.info("Match: {}".format(stat.match['oxm_fields']))
            #self.logger.info("byte_count: {} ".format(stat.match['ipv4_src']))
            #if stat.byte_count > 1500:
            #self.current_priority = self.current_priority - 5
            ipv4_src = stat.match.get('ipv4_src')
            ipv4_dst = stat.match.get('ipv4_dst')
            tcp_dst = stat.match.get('tcp_dst')
            tcp_src = stat.match.get('tcp_src')
            udp_dst = stat.match.get('udp_dst')
            udp_src = stat.match.get('udp_src')
            ip_proto = stat.match.get('ip_proto')

                

            #print(type(self.datapaths[5]))

            if stat.byte_count > self.elephant_treshold:
                route_list = [ r for r in self.routes if r != self.current_route ]
                self.current_route = random.choice(route_list)
                random_route = self.current_route
                self.current_priority = self.current_priority + 1
                print("New Route {} !!!!!!!!!!!!! New Route {}".format(random_route,random_route))
                #random_route = 3
                #self.current_route = random_route
                
                if ip_proto == 1:
                    print("ICMP PACKET")
                    args = {'in_port':2,'eth_type':0x0800,'ipv4_src':ipv4_src,'ipv4_dst':ipv4_dst,'ip_proto':ip_proto}
                elif ip_proto == 6:
                    args = {'in_port':2,'eth_type':0x0800,'ipv4_src':ipv4_src,'ipv4_dst':ipv4_dst,'ip_proto':ip_proto,'tcp_src':tcp_src,'tcp_dst':tcp_dst}
                elif ip_proto == 17:
                    args = {'in_port':2,'eth_type':0x0800,'ipv4_src':ipv4_src,'ipv4_dst':ipv4_dst,'ip_proto':ip_proto,'udp_src':udp_src,'udp_dst':udp_dst}

                if ipv4_src == self.h1ip:
                    if ip_proto in [1,6,17]:
                        if random_route == 1:
                            args['in_port'] = 2
                            match = self.datapaths[5].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[5].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[5], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            
                            args['in_port']=1
                            match = self.datapaths[2].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[2].ofproto_parser.OFPActionOutput(2)]
                            self.add_flow(self.datapaths[2], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)

                            args['in_port']=1
                            match = self.datapaths[1].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[1].ofproto_parser.OFPActionOutput(2)]
                            self.add_flow(self.datapaths[1], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            print("Flow added")
                            self.flow_in = True

                        elif random_route == 2:
                            args['in_port'] = 3
                            match = self.datapaths[5].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[5].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[5], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            
                            args['in_port']=1
                            match = self.datapaths[3].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[3].ofproto_parser.OFPActionOutput(2)]
                            self.add_flow(self.datapaths[3], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)

                            args['in_port']=1
                            match = self.datapaths[1].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[1].ofproto_parser.OFPActionOutput(3)]
                            self.add_flow(self.datapaths[1], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            print("Flow added")
                            self.flow_in = True

                        elif random_route == 3:
                            args['in_port'] = 4
                            match = self.datapaths[5].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[5].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[5], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            
                            args['in_port']=1
                            match = self.datapaths[4].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[4].ofproto_parser.OFPActionOutput(2)]
                            self.add_flow(self.datapaths[4], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)

                            args['in_port']=1
                            match = self.datapaths[1].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[1].ofproto_parser.OFPActionOutput(4)]
                            self.add_flow(self.datapaths[1], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            print("Flow added")
                            self.flow_in = True

                if ipv4_src == self.h2ip:
                    if ip_proto in [1,6,17]:
                        if random_route == 1:
                            args['in_port'] = 1
                            match = self.datapaths[5].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[5].ofproto_parser.OFPActionOutput(2)]
                            self.add_flow(self.datapaths[5], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            
                            args['in_port']=2
                            match = self.datapaths[2].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[2].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[2], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)

                            args['in_port']=2
                            match = self.datapaths[1].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[1].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[1], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            print("Flow added")
                            self.flow_out = True
                    
                        elif random_route == 2:
                            args['in_port'] = 1
                            match = self.datapaths[5].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[5].ofproto_parser.OFPActionOutput(3)]
                            self.add_flow(self.datapaths[5], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            
                            args['in_port']=2
                            match = self.datapaths[3].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[3].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[3], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)

                            args['in_port']=3
                            match = self.datapaths[1].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[1].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[1], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            print("Flow added")
                            self.flow_in = True

                        elif random_route == 3:
                            args['in_port'] = 1
                            match = self.datapaths[5].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[5].ofproto_parser.OFPActionOutput(4)]
                            self.add_flow(self.datapaths[5], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            
                            args['in_port']=2
                            match = self.datapaths[4].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[4].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[4], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)

                            args['in_port']=4
                            match = self.datapaths[1].ofproto_parser.OFPMatch(**args)
                            actions = [self.datapaths[1].ofproto_parser.OFPActionOutput(1)]
                            self.add_flow(self.datapaths[1], self.current_priority, match, actions,idle_timeout=self.new_route_timeout)
                            print("Flow added")
                            self.flow_in = True

            

    def add_flow(self, datapath, priority, match, actions,idle_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        
        ofproto = datapath.ofproto
        #self.logger.info(msg.data)
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        layer4_header = None
        try:
            layer4_header = layer4_header = pkt.protocols[2]
        except IndexError:
            pass
        
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            pass
            #print("ARP packet DETECTED !!!!!!!!!!!!!!!!!")
        else:
            pass
            # print("Ip Src: {}".format(ipv4_pkt.src))
            # print("Ip Dest: {}".format(ipv4_pkt.dst))
            # print("Protocol Name: {}".format(layer4_header.protocol_name))
            # print("Src Port: {}".format(layer4_header.src_port))
            # print("Dst Port: {}".format(layer4_header.dst_port))
       
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        
        dpid_id = int(dpid)
        print("DPID: {}".format(dpid_id))
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port


        if self.current_route == 1:
            out_port = self.route1(dpid_id,in_port)
        elif self.current_route == 2:
            out_port = self.route2(dpid_id,in_port)
        elif self.current_route == 3:
            out_port = self.route3(dpid_id,in_port)

        try:
            out_port
        except NameError:
            out_port = ofproto.OFPP_FLOOD 
        

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD and arp_pkt is None:
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.flowid = self.flowid + 1
            if layer4_header.protocol_name == "arp":
                    match = parser.OFPMatch(in_port=in_port,
                        eth_dst=dst,
                        eth_src=src,
                        eth_type=0x0806
                        )
            if layer4_header.protocol_name == "icmp":
                match = parser.OFPMatch(in_port=in_port,
                        eth_dst=dst,
                        eth_src=src,
                        eth_type=0x0800,
                        ipv4_src=ipv4_pkt.src,
                        ipv4_dst=ipv4_pkt.dst,
                        ip_proto=1
                        )
            if layer4_header.protocol_name == "tcp":
                match = parser.OFPMatch(in_port=in_port,
                                        eth_dst=dst,
                                        eth_src=src,
                                        eth_type=0x0800,
                                        ipv4_src=ipv4_pkt.src,
                                        ipv4_dst=ipv4_pkt.dst,
                                        ip_proto=6,
                                        tcp_src=layer4_header.src_port,
                                        tcp_dst=layer4_header.dst_port)
            
            if layer4_header.protocol_name == "udp":
                match = parser.OFPMatch(in_port=in_port,
                                        eth_dst=dst,
                                        eth_src=src,
                                        eth_type=0x0800,
                                        ipv4_src=ipv4_pkt.src,
                                        ipv4_dst=ipv4_pkt.dst,
                                        ip_proto=17,
                                        udp_src=layer4_header.src_port,
                                        udp_dst=layer4_header.dst_port)
         
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1000, match, actions, msg.buffer_id,idle_timeout=15)
                #self.datapaths[datapath.id] = (datapath,match)
            else:
                self.add_flow(datapath, 1000, match, actions,idle_timeout=15)
                #self.datapaths[datapath.id] = (datapath,match)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        