error {
    INTHeaderTooShort,
    INTMetaTooLong
}
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

header my_vxlan_gpe_t {
    bit<8>  flags;
    bit<16> nextHop;
    bit<8>  nextProto;
    vni_t   vni;
    bit<8>  rsvd2;
}

typedef bit<8> trace_t;
typedef bit<8> fi_t;
typedef bit<2> mark_t;
typedef bit<24> fv_t;
typedef bit<8> ft_t;
header feature_t {
    fv_t   featValue;
    bit<8> nextProto;
}

header int_shim_t {
    bit<4> teleType;
    bit<4> rsvd;
    bit<8> len;
    bit<1> G;
    bit<7> rsvd2;
    bit<8> nextProto;
}

header int_md_t {
    bit<4>  version;
    bit<3>  flags;
    bit<12> rsvd;
    bit<5>  hopML;
    bit<8>  remainingHop;
    bit<16> instrBitmap;
    bit<16> domainID;
    bit<16> dsInstr;
    bit<16> dsFlags;
}

header switch_t {
    bit<16> swID;
    bit<16> weightTx;
}

const bit<8> FEATTYPE_FEAT = 0x80;
const bit<8> INT_SHIM = 0x82;
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
    bit<8>            remaining;
}

struct source_header_t {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          outer_ethernet;
    eth_type_t          outer_eth_type;
    ipv4_t              outer_ipv4;
    udp_t               outer_udp;
    my_vxlan_gpe_t      vxlan;
    feature_t[8]        features;
    int_shim_t          int_shim;
    int_md_t            int_md;
    switch_t[4]         swtraces;
    ethernet_t          ethernet;
    vlan_tag_t          vlan_tag;
    eth_type_t          eth_type;
    ipv4_t              ipv4;
    ipv6_t              ipv6;
    l4_union_t          l4_union;
}

parser VxlanSourceGPEParser(packet_in pkt, out source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
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
            ETHERTYPE_IPV6: parse_ipv6;
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
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        gmeta.lkp.l4_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
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

control VxlanSourceGPEDeparser(packet_out pkt, in source_header_t hdr) {
    apply {
        pkt.emit(hdr.packet_in);
        pkt.emit(hdr.outer_ethernet);
        pkt.emit(hdr.outer_eth_type);
        pkt.emit(hdr.outer_ipv4);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.vxlan);
        pkt.emit(hdr.features);
        pkt.emit(hdr.int_shim);
        pkt.emit(hdr.int_md);
        pkt.emit(hdr.swtraces);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.eth_type);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.l4_union);
    }
}

struct sink_header_t {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          outer_ethernet;
    eth_type_t          outer_eth_type;
    ipv4_t              outer_ipv4;
    udp_t               outer_udp;
    my_vxlan_gpe_t      vxlan;
    int_shim_t          int_shim;
    int_md_t            int_md;
    switch_t[4]         swtraces;
    ethernet_t          ethernet;
    vlan_tag_t          vlan_tag;
    eth_type_t          eth_type;
    ipv4_t              ipv4;
    ipv6_t              ipv6;
}

parser VxlanSinkGPEParser(packet_in pkt, out sink_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
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
        transition select(hdr.vxlan.flags) {
            0xc: parse_vxlan_gpe;
            0x8: parse_ethernet;
            default: accept;
        }
    }
    state parse_vxlan_gpe {
        transition select(hdr.vxlan.nextProto) {
            0x82: parse_int_shim;
            default: parse_ethernet;
        }
    }
    state parse_int_shim {
        pkt.extract(hdr.int_shim);
        verify(hdr.int_shim.len >= 3, error.INTHeaderTooShort);
        gmeta.remaining = hdr.int_shim.len - 3 >> 1;
        transition select(hdr.int_shim.teleType) {
            1: parse_int_md;
            default: accept;
        }
    }
    state parse_int_md {
        pkt.extract(hdr.int_md);
        transition select(gmeta.remaining) {
            0: parse_ethernet;
            default: parse_swtrace;
        }
    }
    state parse_swtrace {
        pkt.extract(hdr.swtraces.next);
        gmeta.remaining = gmeta.remaining - 1;
        transition select(gmeta.remaining) {
            0: parse_ethernet;
            default: parse_swtrace;
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
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        gmeta.lkp.l4_proto = hdr.ipv4.protocol;
        transition accept;
    }
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        gmeta.lkp.l4_proto = hdr.ipv6.next_hdr;
        transition accept;
    }
}

control VxlanSinkGPEDeparser(packet_out pkt, in sink_header_t hdr) {
    apply {
        pkt.emit(hdr.packet_in);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.eth_type);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
    }
}

struct transit_header_t {
    packet_out_header_t packet_out;
    packet_in_header_t  packet_in;
    ethernet_t          outer_ethernet;
    eth_type_t          outer_eth_type;
    ipv4_t              outer_ipv4;
    udp_t               outer_udp;
    my_vxlan_gpe_t      vxlan;
    feature_t[8]        features;
    int_shim_t          int_shim;
    int_md_t            int_md;
    switch_t[4]         swtraces;
}

parser VxlanTransitGPEParser(packet_in pkt, out transit_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
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
        transition select(hdr.vxlan.flags) {
            0xc: parse_vxlan_gpe;
            0x8: accept;
            default: accept;
        }
    }
    state parse_vxlan_gpe {
        transition select(hdr.vxlan.nextProto) {
            FEATTYPE_FEAT: parse_tree_feature;
            INT_SHIM: parse_int_shim;
            default: accept;
        }
    }
    state parse_tree_feature {
        pkt.extract(hdr.features.next);
        transition select(hdr.features.last.nextProto) {
            FEATTYPE_FEAT: parse_tree_feature;
            default: accept;
        }
    }
    state parse_int_shim {
        pkt.extract(hdr.int_shim);
        verify(hdr.int_shim.len >= 3, error.INTHeaderTooShort);
        gmeta.remaining = hdr.int_shim.len - 3 >> 1;
        transition select(hdr.int_shim.teleType) {
            1: parse_int_md;
            default: accept;
        }
    }
    state parse_int_md {
        pkt.extract(hdr.int_md);
        verify(gmeta.remaining <= 4, error.StackOutOfBounds);
        transition select(gmeta.remaining) {
            0: accept;
            default: parse_swtrace;
        }
    }
    state parse_swtrace {
        pkt.extract(hdr.swtraces.next);
        gmeta.remaining = gmeta.remaining - 1;
        transition select(gmeta.remaining) {
            0: accept;
            default: parse_swtrace;
        }
    }
}

control VxlanTransitGPEDeparser(packet_out pkt, in transit_header_t hdr) {
    apply {
        pkt.emit(hdr.packet_in);
        pkt.emit(hdr.outer_ethernet);
        pkt.emit(hdr.outer_eth_type);
        pkt.emit(hdr.outer_ipv4);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.vxlan);
        pkt.emit(hdr.int_shim);
        pkt.emit(hdr.int_md);
        pkt.emit(hdr.swtraces);
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

control updateIPv4UDPChecksum(inout ipv4_t ipv4, inout udp_t udp) {
    apply {
        update_checksum_with_payload(udp.isValid(), { ipv4.src_addr, ipv4.dst_addr, 8w0, 8w17, udp.len, udp.sport, udp.dport, udp.len, 16w0 }, udp.checksum, HashAlgorithm.csum16);
    }
}

control Filtering(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, out bool skip_forwarding) {
    action set_bridege_domain(bridge_domain_t para_bridge_domain) {
        skip_forwarding = false;
        gmeta.bridge_domain = para_bridge_domain;
    }
    action set_skip_forwarding() {
        skip_forwarding = true;
        gmeta.bridge_domain = 0;
    }
    table ingressVlanTable {
        key = {
            im.ingress_port: exact;
            gmeta.vlan_id  : exact;
        }
        actions = {
            set_bridege_domain;
            set_skip_forwarding;
        }
        default_action = set_skip_forwarding();
    }
    apply {
        ingressVlanTable.apply();
    }
}

control PortRetrieve(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, in next_hop_t next_hop) {
    action l3PortRetrieveTable(port_id_t port_id, mac_addr_t dmac) {
        hdr.ethernet.smac = hdr.ethernet.dmac;
        im.egress_spec = port_id;
        hdr.ethernet.dmac = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action l2PortRetrieveTable(port_id_t port_id) {
        im.egress_spec = port_id;
    }
    action vtepRetrieveTable(port_id_t port_id, mac_addr_t smac, mac_addr_t dmac) {
        im.egress_spec = port_id;
        hdr.outer_ethernet.dmac = dmac;
        hdr.outer_ethernet.smac = smac;
        hdr.outer_ipv4.ttl = hdr.outer_ipv4.ttl - 1;
    }
    action _drop() {
        mark_to_drop(im);
    }
    action send_to_cpu() {
        im.egress_spec = 255;
    }
    action clone_to_cpu() {
        clone(CloneType.I2E, 99);
    }
    table PortRetrieveTable {
        key = {
            next_hop: exact;
        }
        actions = {
            l3PortRetrieveTable;
            l2PortRetrieveTable;
            vtepRetrieveTable;
            _drop;
        }
        default_action = _drop();
    }
    apply {
        PortRetrieveTable.apply();
    }
}

control VlanHandling(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, in next_hop_t next_hop) {
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

struct vxlan_metadata_t {
    vni_t       vni;
    ipv4_addr_t src_vtep_ip;
    ipv4_addr_t dst_vtep_ip;
}

control VxlanEncapLogic(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, inout vxlan_metadata_t vxlan_meta, inout bit<16> next_hop) {
    action set_l3_vni(vni_t para_l3_vni, mac_addr_t para_vbdif_dmac) {
        vxlan_meta.vni = para_l3_vni;
        hdr.ethernet.smac = hdr.ethernet.dmac;
        hdr.ethernet.dmac = para_vbdif_dmac;
    }
    table vxlanRoutingTable {
        key = {
            vxlan_meta.vni   : exact;
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            set_l3_vni;
            nop;
        }
        default_action = nop();
    }
    action mappingTableEncap(ipv4_addr_t para_sip, ipv4_addr_t para_dip) {
        vxlan_meta.src_vtep_ip = para_sip;
        vxlan_meta.dst_vtep_ip = para_dip;
    }
    action mappingTableForward(next_hop_t para_next_hop, mac_addr_t para_host_dmac) {
        next_hop = para_next_hop;
        hdr.ethernet.smac = hdr.ethernet.dmac;
        hdr.ethernet.dmac = para_host_dmac;
    }
    table mappingTable {
        key = {
            vxlan_meta.vni   : exact;
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            mappingTableEncap;
            mappingTableForward;
            nop;
        }
        default_action = nop();
    }
    action vxlan_encap() {
        hdr.outer_ethernet.setValid();
        hdr.outer_eth_type.setValid();
        hdr.outer_ipv4.setValid();
        hdr.outer_udp.setValid();
        hdr.vxlan.setValid();
        hdr.vxlan.flags = 0xc;
        hdr.vxlan.nextProto = 0x3;
        hdr.vxlan.vni = vxlan_meta.vni;
        hdr.outer_udp.sport = gmeta.flow_id;
        hdr.outer_udp.dport = 4789;
        hdr.outer_udp.len = (bit<16>)im.packet_length + 16w16;
        hdr.outer_ipv4.version = 4w4;
        hdr.outer_ipv4.ihl = 4w5;
        hdr.outer_ipv4.total_len = hdr.outer_udp.len + 16w20;
        hdr.outer_ipv4.ttl = 8w64;
        hdr.outer_ipv4.src_addr = vxlan_meta.src_vtep_ip;
        hdr.outer_ipv4.dst_addr = vxlan_meta.dst_vtep_ip;
        hdr.outer_ipv4.protocol = PROTO_UDP;
        hdr.outer_eth_type.value = ETHERTYPE_IPV4;
    }
    action set_next_hop(next_hop_t para_next_hop) {
        next_hop = para_next_hop;
    }
    table vtepForwardTable {
        key = {
            vxlan_meta.dst_vtep_ip: exact;
        }
        actions = {
            set_next_hop;
        }
    }
    apply {
        vxlanRoutingTable.apply();
        switch (mappingTable.apply().action_run) {
            mappingTableEncap: {
                vxlan_encap();
                vtepForwardTable.apply();
            }
            mappingTableForward: 
            default: {
            }
        }
    }
}

control VxlanSource(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, inout bit<16> next_hop) {
    vxlan_metadata_t vxlan_meta;
    action bdTunnelTable(vni_t para_l2_vni) {
        vxlan_meta.vni = para_l2_vni;
    }
    action bdLocalTable(next_hop_t para_next_hop) {
        next_hop = para_next_hop;
    }
    table bdTable {
        key = {
            gmeta.bridge_domain: exact;
            hdr.ethernet.dmac  : exact;
        }
        actions = {
            bdTunnelTable;
            bdLocalTable;
            nop;
        }
        default_action = nop();
    }
    apply {
        if (hdr.ipv4.isValid()) {
            switch (bdTable.apply().action_run) {
                bdTunnelTable: {
                    VxlanEncapLogic.apply(hdr, gmeta, im, vxlan_meta, next_hop);
                }
                bdLocalTable: {
                }
                default: {
                    next_hop = 0;
                }
            }
        }
    }
}

control ACL(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im, inout bit<16> next_hop) {
    action send_to_cpu() {
        next_hop = 255;
    }
    action clone_to_cpu() {
        next_hop = 254;
    }
    action drop() {
        next_hop = 511;
    }
    table aclTable {
        key = {
            im.ingress_port   : ternary;
            hdr.ethernet.dmac : ternary;
            hdr.ethernet.smac : ternary;
            hdr.eth_type.value: ternary;
            gmeta.lkp.l4_proto: ternary;
            gmeta.lkp.l4_sport: ternary;
            gmeta.lkp.l4_dport: ternary;
        }
        actions = {
            send_to_cpu;
            clone_to_cpu;
            drop;
        }
        @name("acl_table_counter") counters = direct_counter(CounterType.packets_and_bytes);
    }
    apply {
        aclTable.apply();
    }
}

control IngressImpl(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    bool skip_forwarding = false;
    next_hop_t next_hop = 0;
    action do_hash() {
        hash(gmeta.flow_id, HashAlgorithm.crc16, 16w0, { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, gmeta.lkp.l4_sport, gmeta.lkp.l4_dport }, (17w1 << 16) - 1);
    }
    apply {
        if (hdr.packet_out.isValid()) {
            im.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }
        do_hash();
        Filtering.apply(hdr, gmeta, im, skip_forwarding);
        if (skip_forwarding == false) {
            VxlanSource.apply(hdr, gmeta, im, next_hop);
        }
        PortRetrieve.apply(hdr, gmeta, im, next_hop);
        VlanHandling.apply(hdr, gmeta, im, next_hop);
    }
}

control INTSource(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    apply {
        hdr.int_shim.setValid();
        hdr.int_shim.nextProto = hdr.vxlan.nextProto;
        hdr.vxlan.nextProto = 0x82;
        hdr.int_shim.teleType = 1;
        hdr.int_shim.len = 3;
        hdr.int_shim.G = 0;
        hdr.int_md.setValid();
        hdr.int_md.version = 2;
        hdr.int_md.flags = 0;
        hdr.int_md.hopML = 2;
        hdr.int_md.remainingHop = 4;
        hdr.int_md.instrBitmap = 0x8100;
    }
}

control INTTransit(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    bit<16> tmpswID;
    action insertINTMeta() {
        hdr.int_md.remainingHop = hdr.int_md.remainingHop - 1;
        hdr.swtraces.push_front(1);
        hdr.swtraces[0].setValid();
        hdr.swtraces[0].swID = tmpswID;
        random(hdr.swtraces[0].weightTx, 16w1, 16w7);
        hdr.int_shim.len = hdr.int_shim.len + (bit<8>)hdr.int_md.hopML;
    }
    apply {
        tmpswID = (bit<16>)(4 - hdr.int_md.remainingHop);
        insertINTMeta();
    }
}

control Satistic(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    action insertFeature(in bit<8> featID) {
        hdr.features[featID].setValid();
        hdr.features[featID].nextProto = hdr.vxlan.nextProto;
        random(hdr.features[featID].featValue, 0x0, 0xffffff);
        hdr.vxlan.nextProto = 0x80;
    }
    apply {
        insertFeature(7);
        insertFeature(6);
        insertFeature(5);
        insertFeature(4);
        insertFeature(3);
        insertFeature(2);
        insertFeature(1);
        insertFeature(0);
    }
}

control EgressImpl(inout source_header_t hdr, inout global_metadata_t gmeta, inout standard_metadata_t im) {
    apply {
        if (im.egress_port == 255) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = im.ingress_port;
            exit;
        }
        Satistic.apply(hdr, gmeta, im);
    }
}

control VerifyChecksumImpl(inout source_header_t hdr, inout global_metadata_t gmeta) {
    apply {
    }
}

control ComputeChecksumImpl(inout source_header_t hdr, inout global_metadata_t gmeta) {
    apply {
        updateIPv4Checksum.apply(hdr.ipv4);
        updateIPv4Checksum.apply(hdr.outer_ipv4);
    }
}

V1Switch(VxlanSourceGPEParser(), VerifyChecksumImpl(), IngressImpl(), EgressImpl(), ComputeChecksumImpl(), VxlanSourceGPEDeparser()) main;
