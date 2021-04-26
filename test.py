# Copyright 2017 Wildan Maulana Syahidillah

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp, ipv6, icmp
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import mac, hub
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from thread import start_new_thread
import time

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {} # maps dpid to switch object
        self.arp_table = {} # maps IP to MAC
        self.controller_mac = "dd:dd:dd:dd:dd:dd" # decoy MAC
        self.controller_ip = "10.0.0.100" # decoy IP
        # self.server_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"] # server IPs to monitor
        self.server_ips_s1 = ["10.0.0.1", "10.0.0.2"]
        self.server_ips_s2 = ["10.0.0.3", "10.0.0.4", "10.0.0.5"]
        self.server_ips_s3 = ["10.0.0.6", "10.0.0.7"]
        self.server_switch_1 = 1  # switch dpid with connections to the servers
        self.server_switch_2 = 2
        self.server_switch_3 = 3
        self.latency = {} # maps IP to the latency value

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("opfswitchfeatures")
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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        print("add_flow")
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

    """
        Monitors server latency periodically for 1 second
    """
    def monitor_server_latency(self):
        switch = self.datapath_list[self.server_switch]
        while True:
            hub.sleep(1)
            for server in self.server_ips:
                if server in self.arp_table:
                    self.send_ping_packet(switch, server)
    def monitor_server_latency_1(self):
        print("monitor_server_latency_1")
        switch = self.datapath_list[self.server_switch_1]
        # print("self.datapath_list:", self.datapath_list)
        # print("self.server_switch:", self.server_switch_1)
        while True:
            hub.sleep(1)
            # print(1)
            for server in self.server_ips_s1:
                print("self.arp_table:", self.arp_table)
                if server in self.arp_table:
                    self.send_ping_packet(switch, server)
    def monitor_server_latency_2(self):
        print("monitor_server_latency_2")
        switch = self.datapath_list[self.server_switch_2]
        # print("self.datapath_list:", self.datapath_list)
        # print("self.server_switch:", self.server_switch_2)
        while True:
            hub.sleep(1)
            # print(2)
            for server in self.server_ips_s2:
                print("self.arp_table:", self.arp_table)
                if server in self.arp_table:
                    self.send_ping_packet(switch, server)
    def monitor_server_latency_3(self):
        print("monitor_server_latency_3")
        switch = self.datapath_list[self.server_switch_3]
        # print("self.datapath_list:", self.datapath_list)
        # print("self.server_switch:", self.server_switch_3)
        while True:
            hub.sleep(1)
            # print(3)
            for server in self.server_ips_s3:
                print("self.arp_table:", self.arp_table)
                if server in self.arp_table:
                    self.send_ping_packet(switch, server)

    def send_ping_packet(self, switch, ip):
        print("send_ping_packet")
        datapath = switch.dp
        dpid = datapath.id
        mac_dst = self.arp_table[ip]
        out_port = self.mac_to_port[dpid][mac_dst]
        print("mac_dst:", mac_dst)
        print("out_port:", out_port)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,
                                            src=self.controller_mac,
                                            dst=self.arp_table[ip]))
        pkt.add_protocol(ipv4.ipv4(proto=in_proto.IPPROTO_ICMP,
                                    src=self.controller_ip,
                                    dst=ip))
        echo_payload = "%d;%s;%f" % (dpid, ip, time.time())
        payload = icmp.echo(data=echo_payload)
        pkt.add_protocol(icmp.icmp(data=payload))
        pkt.serialize()

        out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                data=pkt.data,
                in_port=datapath.ofproto.OFPP_CONTROLLER,
                actions=actions
            )

        datapath.send_msg(out)

    def ping_packet_handler(self, pkt):
        print("ping_packet_handler")
        icmp_packet = pkt.get_protocol(icmp.icmp)
        echo_payload = icmp_packet.data
        payload = echo_payload.data
        info = payload.split(";")
        switch = info[0]
        ip = info[1]
        latency = (time.time() - float(info[2])) * 1000 # in ms
        print "ip %s connected to s%s latency = %f ms" % (ip, switch, latency)
        self.latency[ip] = latency

    """
        Initializes ARP entries for the controller decoy addresses
    """
    def request_arp(self, datapath, ip):
        print("request_arp")
        print("datapath:", datapath.id)
        print("ip:", ip)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        ARP_Request = packet.Packet()

        ARP_Request.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=mac.BROADCAST_STR,
            src=self.controller_mac))
        ARP_Request.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=self.controller_mac,
            src_ip=self.controller_ip,
            dst_mac=mac.BROADCAST_STR,
            dst_ip=ip))
        print("**************************** request_arp *******************************")
        print("datapath:", datapath.id)
        print("ip:", ip)
        print("request_arp_dst_mac:", mac.BROADCAST_STR)
        print("request_arp_dst_ip:", ip)
        print("request_arp_src_mac:",self.controller_mac)
        print("request_arp_src_ip:", self.controller_ip)
        print("request_arp_action:    OPFF_FLOOD")
        print("**************************** request_arp *******************************")

        ARP_Request.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=ARP_Request.data)
        datapath.send_msg(out)

    """
        This is needed to resolve the decoy controller ARP entries
        for ARP poisoning prevention systems, by replying ARP
        requests sent to the controller.
    """
    def reply_arp(self, datapath, eth_dst, ip_dst, in_port):
        print("reply_arp")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        ARP_Reply = packet.Packet()

        ARP_Reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_dst,
            src=self.controller_mac))
        ARP_Reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.controller_mac,
            src_ip=self.controller_ip,
            dst_mac=eth_dst,
            dst_ip=ip_dst))

        ARP_Reply.serialize()
        
        print("**************************** reply_arp *******************************")
        print("reply_arp_dst_mac:", eth_dst)
        print("reply_arp_dst_ip:", ip_dst)
        print("reply_arp_src_mac:",self.controller_mac)
        print("reply_arp_src_ip:", self.controller_ip)
        print("reply_arp_action:", in_port)
        print("**************************** reply_arp *******************************")

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=ARP_Reply.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print("packet_in_handler")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        
        print("**************************** packet in *******************************")
        print("dpid:", dpid)
        # print("in_port:",in_port)
        print("packet_in_dst_mac:", dst)
        print("packet_in_src_mac:", src)
        # print("reply_arp_src_ip:", self.controller_ip)
        # print("reply_arp_action:", in_port)
        print("**************************** packet in *******************************")

        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        print("self.mac_to_port", self.mac_to_port)

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            print("**************************** packet in, arp_pkt ture*******************************")
            print("arp_pkt ture")
            dst_ip = arp_pkt.dst_ip
            src_ip = arp_pkt.src_ip
            print("dst_ip:", dst_ip)
            print("src_ip", src_ip)
            if dst != mac.BROADCAST_STR:
                self.arp_table[arp_pkt.dst_ip] = dst
                self.arp_table[arp_pkt.src_ip] = src
                print("self.arp_table of ", self.arp_table)
                print("**************************** packet in, arp_pkt ture*******************************")
            else:
                print("enter reply_arp")
                print("**************************** packet in, arp_pkt ture*******************************")
                self.reply_arp(datapath, src, src_ip, in_port)
        elif dst == self.controller_mac:
            print("dst = self.controller")
            self.ping_packet_handler(pkt)

        if dst in self.mac_to_port[dpid]:
            print("dst in self.mac_to_port[dpid]")
            out_port = self.mac_to_port[dpid][dst]
        else:
            print("self.mac_to_port:", self.mac_to_port)
            print("dst not in self.mac_to_port[dpid],so, outport = flood")
            out_port = ofproto.OFPP_FLOOD
        print("final out_port:", out_port)

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            print("if not flood")
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
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

    # @set_ev_cls(event.EventSwitchEnter)
    # def switch_enter_handler(self, event):
    #     switch = event.switch
    #     ofp_parser = switch.dp.ofproto_parser
    #     if switch.dp.id not in self.datapath_list:
    #         self.datapath_list[switch.dp.id] = switch
    #     if switch.dp.id == self.server_switch:
    #         for server in self.server_ips:
    #             self.request_arp(switch.dp, server)
    #         start_new_thread(self.monitor_server_latency, )


    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        switch = event.switch
        ofp_parser = switch.dp.ofproto_parser
        if switch.dp.id not in self.datapath_list:
            self.datapath_list[switch.dp.id] = switch
        # if switch.dp.id == self.server_switch:
        #     for server in self.server_ips:
        #         self.request_arp(switch.dp, server)
        #     start_new_thread(self.monitor_server_latency, )
        if switch.dp.id == self.server_switch_1:
            # print("switch.dp.id", switch.dp.id)
            # print("self.server_switch_1:", self.server_switch_1)
            for server in self.server_ips_s1:
                self.request_arp(switch.dp, server)
            start_new_thread(self.monitor_server_latency_1, )
        if switch.dp.id == self.server_switch_2:
            print("switch.dp.id", switch.dp.id)
            print("self.server_switch_2:", self.server_switch_2)
            for server in self.server_ips_s2:
                self.request_arp(switch.dp, server)
            start_new_thread(self.monitor_server_latency_2, )
        if switch.dp.id == self.server_switch_3:
            print("switch.dp.id", switch.dp.id)
            print("self.server_switch_3:", self.server_switch_3)
            for server in self.server_ips_s3:
                self.request_arp(switch.dp, server)
            start_new_thread(self.monitor_server_latency_3, )