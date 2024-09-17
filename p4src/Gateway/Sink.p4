#include <core.p4>
#define V1MODEL_VERSION 20221001
#include <v1model.p4>

typedef bit<3> fwd_type_t;
typedef bit<16> next_hop_t;
typedef bit<20> mpls_label_t;
typedef bit<9> port_id_t;
typedef bit<48> mac_addr_t;
typedef bit<16> mcast_group_id_t;
typedef bit<12> vlan_id_t;
typedef bit<2> port_type_t;
const port_type_t PORT_TYPE_UNKNOWN = 0x0;
const port_type_t PORT_TYPE_EDGE = 0x1;
const port_type_t PORT_TYPE_INFRA = 0x2;
const port_type_t PORT_TYPE_INTERNAL = 0x3;
const vlan_id_t DEFAULT_VLAN_ID = 0;
action nop() {
    NoAction();
}
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16> l4_port_t;
typedef bit<24> vni_t;
typedef bit<8> bridge_domain_t;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const l4_port_t UDPPORT_VXLAN = 4789;
const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_ICMPV6 = 58;
@controller_header("packet_in") header packet_in_header_t {
    port_id_t ingress_port;
    bit<7>    _pad;
}

@controller_header("packet_out") header packet_out_header_t {
    port_id_t egress_port;
    bit<7>    _pad;
}

header ethernet_t {
    mac_addr_t dmac;
    mac_addr_t smac;
}

header eth_type_t {
    bit<16> value;
}

header vlan_tag_t {
    bit<16>   eth_type;
    bit<3>    pri;
    bit<1>    cfi;
    vlan_id_t vlan_id;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<6>      dscp;
    bit<2>      ecn;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_len;
    bit<8>   next_hdr;
    bit<8>   hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header tcp_t {
    l4_port_t sport;
    l4_port_t dport;
    bit<32>   seq_no;
    bit<32>   ack_no;
    bit<4>    data_offset;
    bit<3>    res;
    bit<3>    ecn;
    bit<6>    ctrl;
    bit<16>   window;
    bit<16>   checksum;
    bit<16>   urgent_ptr;
}

header udp_t {
    l4_port_t sport;
    l4_port_t dport;
    bit<16>   len;
    bit<16>   checksum;
}

header_union l4_union_t {
    tcp_t tcp;
    udp_t udp;
}

header icmp_t {
    bit<8>  icmp_type;
    bit<8>  icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header vxlan_t {
    bit<8>  flags;
    bit<24> rsvd;
    vni_t   vni;
    bit<8>  rsvd2;
}

struct header_t {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          outer_ethernet;
    eth_type_t          outer_eth_type;
    ipv4_t              outer_ipv4;
    udp_t               outer_udp;
    vxlan_t             vxlan;
    ethernet_t          ethernet;
    vlan_tag_t          vlan_tag;
    eth_type_t          eth_type;
    ipv4_t              ipv4;
    l4_union_t          l4_union;
}

struct lookup_metadata_t {
    bit<8>    l4_proto;
    l4_port_t l4_sport;
    l4_port_t l4_dport;
}

struct global_metadata_t {
    lookup_metadata_t lkp;
    vlan_id_t         vlan_id;
    bridge_domain_t   bridge_domain;
    bit<16>           flow_id;
}

parser VxlanSourceParser(packet_in pkt, out header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    state start {
        transition select(im.ingress_port) {
            255: parse_packet_out;
            default: parse_ethernet;
        }
    }
    state parse_packet_out {
        pkt.extract(hdr.packet_out);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        gmeta.vlan_id = DEFAULT_VLAN_ID;
        transition select(pkt.lookahead<bit<16>>()) {
            ETHERTYPE_VLAN: parse_vlan_tag;
            default: parse_eth_type;
        }
    }
    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        gmeta.vlan_id = hdr.vlan_tag.vlan_id;
        transition parse_eth_type;
    }
    state parse_eth_type {
        pkt.extract(hdr.eth_type);
        transition select(hdr.eth_type.value) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        gmeta.lkp.l4_proto = hdr.ipv4.protocol;
        transition select(gmeta.lkp.l4_proto) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.l4_union.tcp);
        gmeta.lkp.l4_sport = hdr.l4_union.tcp.sport;
        gmeta.lkp.l4_dport = hdr.l4_union.tcp.dport;
        transition accept;
    }
    state parse_udp {
        pkt.extract(hdr.l4_union.udp);
        gmeta.lkp.l4_sport = hdr.l4_union.udp.sport;
        gmeta.lkp.l4_dport = hdr.l4_union.udp.dport;
        transition accept;
    }
}

control VxlanSourceDeparser(packet_out pkt, in header_t hdr) {
    apply {
        pkt.emit(hdr.packet_in);
        pkt.emit(hdr.outer_ethernet);
        pkt.emit(hdr.outer_eth_type);
        pkt.emit(hdr.outer_ipv4);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.vxlan);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.eth_type);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.l4_union);
    }
}

parser VxlanSinkParser(packet_in pkt, out header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    state start {
        transition select(im.ingress_port) {
            255: parse_packet_out;
            default: parse_outer_ethernet;
        }
    }
    state parse_packet_out {
        pkt.extract(hdr.packet_out);
        transition parse_outer_ethernet;
    }
    state parse_outer_ethernet {
        pkt.extract(hdr.outer_ethernet);
        transition parse_outer_eth_type;
    }
    state parse_outer_eth_type {
        pkt.extract(hdr.outer_eth_type);
        transition select(hdr.outer_eth_type.value) {
            ETHERTYPE_IPV4: parse_outer_ipv4;
            default: accept;
        }
    }
    state parse_outer_ipv4 {
        pkt.extract(hdr.outer_ipv4);
        gmeta.lkp.l4_proto = hdr.outer_ipv4.protocol;
        transition select(gmeta.lkp.l4_proto) {
            PROTO_UDP: parse_outer_udp;
            default: accept;
        }
    }
    state parse_outer_udp {
        pkt.extract(hdr.outer_udp);
        gmeta.lkp.l4_dport = hdr.outer_udp.dport;
        transition select(gmeta.lkp.l4_dport) {
            UDPPORT_VXLAN: parse_vxlan;
            default: accept;
        }
    }
    state parse_vxlan {
        pkt.extract(hdr.vxlan);
        transition select(hdr.vxlan.flags[2:2]) {
            0: parse_ethernet;
            default: accept;
        }
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        gmeta.vlan_id = DEFAULT_VLAN_ID;
        transition select(pkt.lookahead<bit<16>>()) {
            ETHERTYPE_VLAN: parse_vlan_tag;
            default: parse_eth_type;
        }
    }
    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        gmeta.vlan_id = hdr.vlan_tag.vlan_id;
        transition parse_eth_type;
    }
    state parse_eth_type {
        pkt.extract(hdr.eth_type);
        transition select(hdr.eth_type.value) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        gmeta.lkp.l4_proto = hdr.ipv4.protocol;
        transition select(gmeta.lkp.l4_proto) {
            default: accept;
        }
    }
}

control VxlanSinkDeparser(packet_out pkt, in header_t hdr) {
    apply {
        pkt.emit(hdr.packet_in);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.eth_type);
        pkt.emit(hdr.ipv4);
    }
}

parser VxlanTransitParser(packet_in pkt, out header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    state start {
        transition parse_outer_ethernet;
    }
    state parse_outer_ethernet {
        pkt.extract(hdr.outer_ethernet);
        transition parse_outer_eth_type;
    }
    state parse_outer_eth_type {
        pkt.extract(hdr.outer_eth_type);
        transition select(hdr.outer_eth_type.value) {
            ETHERTYPE_IPV4: parse_outer_ipv4;
            default: accept;
        }
    }
    state parse_outer_ipv4 {
        pkt.extract(hdr.outer_ipv4);
        gmeta.lkp.l4_proto = hdr.outer_ipv4.protocol;
        transition select(gmeta.lkp.l4_proto) {
            PROTO_UDP: parse_outer_udp;
            default: accept;
        }
    }
    state parse_outer_udp {
        pkt.extract(hdr.outer_udp);
        gmeta.lkp.l4_sport = hdr.outer_udp.sport;
        gmeta.lkp.l4_dport = hdr.outer_udp.dport;
        transition accept;
    }
}

control VxlanTransitDeparser(packet_out pkt, in header_t hdr) {
    apply {
        pkt.emit(hdr.outer_ethernet);
        pkt.emit(hdr.outer_eth_type);
        pkt.emit(hdr.outer_ipv4);
        pkt.emit(hdr.outer_udp);
    }
}

control updateIPv4Checksum(inout ipv4_t ipv4) {
    apply {
        update_checksum(ipv4.isValid(), { ipv4.version, ipv4.ihl, ipv4.dscp, ipv4.ecn, ipv4.total_len, ipv4.identification, ipv4.flags, ipv4.frag_offset, ipv4.ttl, ipv4.protocol, ipv4.src_addr, ipv4.dst_addr }, ipv4.checksum, HashAlgorithm.csum16);
    }
}

control verifyIPv4Checksum(in ipv4_t ipv4) {
    apply {
        verify_checksum(ipv4.isValid(), { ipv4.version, ipv4.ihl, ipv4.dscp, ipv4.ecn, ipv4.total_len, ipv4.identification, ipv4.flags, ipv4.frag_offset, ipv4.ttl, ipv4.protocol, ipv4.src_addr, ipv4.dst_addr }, ipv4.checksum, HashAlgorithm.csum16);
    }
}

control PortRetrieve(inout header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, in next_hop_t next_hop) {
    action l3PortRetrieveTable(port_id_t port_id, mac_addr_t dmac) {
        hdr.ethernet.smac = hdr.ethernet.dmac;
        im.egress_spec = port_id;
        hdr.ethernet.dmac = dmac;
    }
    action l2PortRetrieveTable(port_id_t port_id) {
        im.egress_spec = port_id;
    }
    table PortRetrieveTable {
        key = {
            next_hop: exact;
        }
        actions = {
            l3PortRetrieveTable;
            l2PortRetrieveTable;
            nop;
        }
        default_action = nop();
    }
    apply {
        PortRetrieveTable.apply();
    }
}

control VlanHandling(inout header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, in next_hop_t next_hop) {
    action push_vlan() {
        hdr.vlan_tag.setValid();
        hdr.vlan_tag.eth_type = ETHERTYPE_VLAN;
        hdr.vlan_tag.vlan_id = gmeta.vlan_id;
    }
    action pop_vlan() {
        hdr.vlan_tag.setInvalid();
    }
    table vlanUpdateTable {
        key = {
            next_hop     : exact;
            gmeta.vlan_id: exact;
        }
        actions = {
            push_vlan;
            pop_vlan;
            nop;
        }
        default_action = nop();
    }
    apply {
        vlanUpdateTable.apply();
    }
}

control VxlanSink(inout header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, inout bit<16> next_hop) {
    action l2VniForward(bridge_domain_t para_bridge_domain) {
        gmeta.bridge_domain = para_bridge_domain;
    }
    action l3VniForward(bridge_domain_t para_bridge_domain, mac_addr_t dmac) {
        gmeta.bridge_domain = para_bridge_domain;
        hdr.ethernet.smac = hdr.ethernet.dmac;
        hdr.ethernet.dmac = dmac;
    }
    table vniToBridgeTable {
        key = {
            hdr.vxlan.vni    : exact;
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            l2VniForward;
            l3VniForward;
            nop;
        }
        default_action = nop();
    }
    action bdLocalForward(next_hop_t para_next_hop) {
        next_hop = para_next_hop;
    }
    table bdLocalTable {
        key = {
            gmeta.bridge_domain: exact;
            hdr.ethernet.dmac  : exact;
        }
        actions = {
            bdLocalForward;
            nop;
        }
        default_action = nop();
    }
    action vxlan_decap() {
        hdr.outer_ethernet.setInvalid();
        hdr.outer_eth_type.setInvalid();
        hdr.outer_ipv4.setInvalid();
        hdr.outer_udp.setInvalid();
        hdr.vxlan.setInvalid();
    }
    apply {
        if (hdr.vxlan.isValid()) {
            vniToBridgeTable.apply();
            bdLocalTable.apply();
            vxlan_decap();
        }
    }
}

control IngressImpl(inout header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    next_hop_t next_hop = 0;
    apply {
        if (hdr.packet_out.isValid()) {
            im.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }
        VxlanSink.apply(hdr, gmeta, im, next_hop);
        PortRetrieve.apply(hdr, gmeta, im, next_hop);
    }
}

control EgressImpl(inout header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    apply {
        if (im.egress_port == 255) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = im.ingress_port;
            exit;
        }
    }
}

control VerifyChecksumImpl(inout header_t hdr, inout global_metadata_t gmeta) {
    apply {
        verifyIPv4Checksum.apply(hdr.outer_ipv4);
    }
}

control ComputeChecksumImpl(inout header_t hdr, inout global_metadata_t gmeta) {
    apply {
        updateIPv4Checksum.apply(hdr.ipv4);
    }
}

V1Switch(VxlanSinkParser(), VerifyChecksumImpl(), IngressImpl(), EgressImpl(), ComputeChecksumImpl(), VxlanSinkDeparser()) main;
