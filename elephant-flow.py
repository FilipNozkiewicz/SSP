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
        self.current_route = 1
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)
        self.flow_ask = True
        self.routes = [1,2,3]


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
        return out_port

    def monitor(self):
        self.logger.info("start flow monitoring thread")
        while True:
            hub.sleep(3)
            for datapath in self.datapaths.values():
                while self.flow_ask == False:
                    time.sleep(1)
                ofp = datapath.ofproto
                #print(dir(datapath))
                ofp_parser = datapath.ofproto_parser
                req = ofp_parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(req)
                self.flow_id = datapath.id
                self.flow_ask = False
                # mod = ofp_parser.OFPFlowMod(datapath=datapath,table_id=ofp.OFPTT_ALL, command=datapath.ofproto.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
                # datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print("called")

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
        self.datapaths[datapath.id] = datapath

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply,], MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        #print(len(ev.msg.body))
        #print(dir(ev.msg.datapath[0]))
        for stat in ev.msg.body:
            #self.logger.info("Flow details:  %s ",stat)
            print("Flow id: {}".format(self.flow_id))
            self.logger.info("byte_count:  %d ", stat.byte_count)
            # self.logger.info("packet_count:  %d ", stat.packet_count)
            if stat.byte_count > 1500:
                d = self.datapaths[self.flow_id]
                ofp = d.ofproto
                #print(dir(datapath))
                ofp_parser = d.ofproto_parser
                random_route = [ r for r in self.routes if r != self.current_route ]
                self.current_route = random.choice(random_route)
                mod = ofp_parser.OFPFlowMod(datapath=d,table_id=ofp.OFPTT_ALL, command=d.ofproto.OFPFC_DELETE,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
                d.send_msg(mod)
                print("Flow id {} deleted".format(self.flow_id))
            self.flow_ask = True
            

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
    
    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def send_flow_mod(self, datapath):
        # ofp = datapath.ofproto
        # ofp_parser = datapath.ofproto_parser

        # cookie = cookie_mask = 0
        # table_id = 0
        # idle_timeout = hard_timeout = 0
        # priority = 32768
        # buffer_id = ofp.OFP_NO_BUFFER
        # match = ofp_parser.OFPMatch(in_port=1, eth_dst='ff:ff:ff:ff:ff:ff')
        # actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
        # inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
        #                                         actions)]
        # req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
        #                             table_id, ofp.OFPFC_ADD,
        #                             idle_timeout, hard_timeout,
        #                             priority, buffer_id,
        #                             ofp.OFPP_ANY, ofp.OFPG_ANY,
        #                             ofp.OFPFF_SEND_FLOW_REM,
        #                             match, inst)
        # datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # if ev.msg.msg_len < ev.msg.total_len:
        #     self.logger.debug("packet truncated: only %s of %s bytes",
        #                       ev.msg.msg_len, ev.msg.total_len)
        
        
        msg = ev.msg
        datapath = msg.datapath
        
        ofproto = datapath.ofproto
        #self.logger.info(msg.data)
        pkt = packet.Packet(msg.data)
        ipv4_d = ipv4.ipv4(msg.data)
        #self.logger.info(pkt)
        #self.logger.info("######################################")
        # for i in pkt:
        #     #self.logger.info(i) 
        #     print(i)
        #print(pkt.protocols)
        #self.logger.info(pkt)
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
        print("DPID: {}".format(dpid))
        dpid_id = int(dpid)
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        #self.logger.info("Custom message")

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if self.current_route == 1:
            out_port = self.route1(dpid_id,in_port)
        elif self.current_route == 2:
            out_port = self.route2(dpid_id,in_port)
        elif self.current_route == 3:
            out_port = self.route3(dpid_id,in_port)

        


        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD
        #print(out_port)
        #print(in_port)
        
        print("Currrent ROUTE: {}".format(self.current_route))
        try:
            out_port
        except NameError:
            out_port = ofproto.OFPP_FLOOD 

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
