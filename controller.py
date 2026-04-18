"""
SDN Traffic Classifier - Ryu Controller
Classifies incoming packets as TCP, UDP, ICMP, or Other.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, ether_types
from ryu.lib import hub
import datetime
import os

LOG_FILE = "traffic_log.csv"

PROTO_TCP   = 6
PROTO_UDP   = 17
PROTO_ICMP  = 1


class TrafficClassifier(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficClassifier, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self._init_log()
        self.monitor_thread = hub.spawn(self._print_stats)

    # ------------------------------------------------------------------ #
    #  Log init
    # ------------------------------------------------------------------ #
    def _init_log(self):
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("timestamp,src_mac,dst_mac,src_ip,dst_ip,protocol,classification\n")

    def _log(self, src_mac, dst_mac, src_ip, dst_ip, proto_num, label):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"{ts},{src_mac},{dst_mac},{src_ip},{dst_ip},{proto_num},{label}\n")

    # ------------------------------------------------------------------ #
    #  Periodic stats printer
    # ------------------------------------------------------------------ #
    def _print_stats(self):
        while True:
            hub.sleep(10)
            print("\n[STATS] Traffic Classification Summary")
            print("-" * 40)
            total = sum(self.stats.values())
            for label, count in self.stats.items():
                pct = (count / total * 100) if total else 0
                print(f"  {label:<8}: {count:>6} packets  ({pct:5.1f}%)")
            print(f"  {'TOTAL':<8}: {total:>6} packets")
            print("-" * 40)

    # ------------------------------------------------------------------ #
    #  Switch handshake - install table-miss flow
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp      = ev.msg.datapath
        ofp     = dp.ofproto
        parser  = dp.ofproto_parser

        # Table-miss: send every unmatched packet to controller
        match  = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        self.logger.info("[INIT] Switch %s connected.", dp.id)

    # ------------------------------------------------------------------ #
    #  Helper: install a flow entry
    # ------------------------------------------------------------------ #
    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod    = parser.OFPFlowMod(
            datapath=dp, priority=priority,
            idle_timeout=idle, hard_timeout=hard,
            match=match, instructions=inst
        )
        dp.send_msg(mod)

    # ------------------------------------------------------------------ #
    #  Classify by IP protocol number
    # ------------------------------------------------------------------ #
    @staticmethod
    def _classify(proto_num):
        return {PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMP: "ICMP"}.get(proto_num, "Other")

    # ------------------------------------------------------------------ #
    #  PacketIn handler
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg    = ev.msg
        dp     = msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt  = packet.Packet(msg.data)
        eth  = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid    = dp.id

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        out_port = self.mac_to_port[dpid].get(dst_mac, ofp.OFPP_FLOOD)

        # ---- Classification ----
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            proto_num  = ip_pkt.proto
            label      = self._classify(proto_num)
            self.stats[label] += 1
            self._log(src_mac, dst_mac, ip_pkt.src, ip_pkt.dst, proto_num, label)
            self.logger.info(
                "[PKT] %s → %s | %s→%s | PROTO=%d (%s)",
                src_mac, dst_mac, ip_pkt.src, ip_pkt.dst, proto_num, label
            )

            # Install specific flow rules for known protocols (avoid repeated PacketIn)
            if proto_num in (PROTO_TCP, PROTO_UDP, PROTO_ICMP):
                match_kwargs = dict(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=proto_num,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                )
                if proto_num == PROTO_TCP:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    if tcp_pkt:
                        match_kwargs["tcp_dst"] = tcp_pkt.dst_port
                elif proto_num == PROTO_UDP:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    if udp_pkt:
                        match_kwargs["udp_dst"] = udp_pkt.dst_port

                if out_port != ofp.OFPP_FLOOD:
                    match   = parser.OFPMatch(**match_kwargs)
                    actions = [parser.OFPActionOutput(out_port)]
                    self._add_flow(dp, 10, match, actions, idle=30, hard=120)
        else:
            self.stats["Other"] += 1
            self.logger.info("[PKT] Non-IP | %s → %s", src_mac, dst_mac)

        # Forward packet
        actions = [parser.OFPActionOutput(out_port)]
        data    = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out     = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)
