// vim: syntax=P4
/*
    ConQuest: Fine-Grained Queue Measurement in the Data Plane
    
    Copyright (C) 2020 Xiaoqi Chen, Princeton University
    xiaoqic [at] cs.princeton.edu / https://doi.org/10.1145/3359989.3365408
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/


//== Parameters for ConQuest time-windowing
// number of snaps
// CQ_H = 4
// LOG_CQ_H = 2

// snap CMS #rows
// CQ_R = 2

// snap CMS #cols
// CQ_C = 256
// LOG_CQ_C = 8

// Time window T in nanoseconds
// CQ_T = 16384
// LOG_CQ_T = 14

//count bytes
#define SKETCH_INC ((bit<32>) hdr.ipv4.total_len)


// sanity check for parameters
#if (4 != (1<<2))
  #error CQ_H LOG_CQ_H mismatch
#endif
#if (256 != (1<<8))
  #error CQ_C LOG_CQ_C mismatch
#endif
#if (16384 != (1<<14))
  #error CQ_T LOG_CQ_T mismatch
#endif

#if (256> 2445 )
  #warning Snapshot might be too wide, you want at least CQ_C packets per CQ_T nanoseconds to do cyclic cleaning adequately
  //100Gbps=148.8Mpps=6.7ns/pkt
#endif


//== Preamble: constants, headers

#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> diffserv;
    bit<2> ecn; 
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
}

struct paired_32bit {
    bit<32> hi;
    bit<32> lo;
}


//== Metadata definition

struct ig_metadata_t {
}
struct eg_metadata_t {
    bit<8> num_snapshots_to_read;//result of division (delay/T), could be larger than H
    bit<2> snap_epoch;
    bit<18> q_delay;
    
    bit<8> random_bits;
    
    bit<8> cyclic_index;
        bit<8> hashed_index_row_0;
        bit<8> hashed_index_row_1;
    
            bit<8> snap_0_row_0_index;
            bit<32> snap_0_row_0_read;
            bit<8> snap_0_row_1_index;
            bit<32> snap_0_row_1_read;
            bit<8> snap_1_row_0_index;
            bit<32> snap_1_row_0_read;
            bit<8> snap_1_row_1_index;
            bit<32> snap_1_row_1_read;
            bit<8> snap_2_row_0_index;
            bit<32> snap_2_row_0_read;
            bit<8> snap_2_row_1_index;
            bit<32> snap_2_row_1_read;
            bit<8> snap_3_row_0_index;
            bit<32> snap_3_row_0_read;
            bit<8> snap_3_row_1_index;
            bit<32> snap_3_row_1_read;
    
    
        bit<32> snap_0_read_min_l0;
        bit<32> snap_1_read_min_l0;
        bit<32> snap_2_read_min_l0;
        bit<32> snap_3_read_min_l0;
  
    
            bit<32> snap_0_read_min_l1;
            bit<32> snap_2_read_min_l1;
  
            bit<32> snap_0_read_min_l2;
  
  
}


//== Parser and deparser

parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.advance(64); 
        transition accept;
    }

    state parse_port_metadata {
        pkt.advance(64);  //tofino 1 port metadata size
        transition accept;
    }
}

parser EtherIPTCPUDPParser(
    packet_in pkt,
    out header_t hdr) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.ipv4.total_len) {
            default : accept;
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            default: accept;
        }
    }  
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    EtherIPTCPUDPParser() layer4_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {    
    apply {    
        pkt.emit(hdr);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    
    EtherIPTCPUDPParser() layer4_parser;
    state start {
        pkt.extract(eg_intr_md);
        layer4_parser.apply(pkt, hdr);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
        pkt.emit(hdr);
    }
}


//== Control logic 

control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
         
        action drop() {
            ig_intr_dprsr_md.drop_ctl = 0x1; // Mark packet for dropping after ingress.
        }
        action drop_and_exit(){
            drop();exit;  // Stop pipeline processing, and drop packet.
        }
        action nop() {
        }
        
        action route_to_port(bit<9> port){
            ig_intr_tm_md.ucast_egress_port=port;
        }
        action reflect(){
            //send you back to where you're from
            ig_intr_tm_md.ucast_egress_port=ig_intr_md.ingress_port;
        }
           
        table tb_route_ipv4 {
            key = {
                hdr.ipv4.dst_addr : exact;
            }
            actions = {
                route_to_port;
                reflect;
                drop;
            }
            default_action = reflect();
        }
        
        apply {
            tb_route_ipv4.apply();            
        }
}

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    
    action nop(){
    }
    action drop(){
        ig_intr_dprs_md.drop_ctl = 0x1;
    }
    action skip(){
        exit;
    }
    action mark_ECN(){
        hdr.ipv4.ecn=0x3;
    }
    
    
    // Limit to only process traffic for a single egress port.
    // This prototype is single-port version; multi-port version needs memory partitioning.
    action run_conquest(){
        nop();
    }
    table tb_gatekeeper {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            skip;
            run_conquest;
        }
        size = 1;
        default_action = skip();
    }
    
    
    //== Start: What time is it? How long is the queue?
    action prep_epochs(){
        bit<18> q_delay=eg_intr_md.deq_timedelta;
        eg_md.q_delay=q_delay;
        eg_md.num_snapshots_to_read= (bit<8>) (q_delay >> 14);
        // Note: in P4_14 the delay in queuing meta is 32 bits. In P4_16, to recover 32-bit queuing delay, you need to manually bridge a longer timestamp from ingress. 
    
        bit<48> d_i=eg_intr_md_from_prsr.global_tstamp;
        //bit<18> a_i=eg_intr_md.enq_tstamp;
        eg_md.snap_epoch=d_i[14+2-1:14];
        // floor(d_i / T) % h
    }
    
    action prep_reads(){
                eg_md.snap_0_row_0_read=0;
                eg_md.snap_0_row_1_read=0;
                eg_md.snap_1_row_0_read=0;
                eg_md.snap_1_row_1_read=0;
                eg_md.snap_2_row_0_read=0;
                eg_md.snap_2_row_1_read=0;
                eg_md.snap_3_row_0_read=0;
                eg_md.snap_3_row_1_read=0;
    }
    
    Random< bit<8> >() rng;
    action prep_random(){
        eg_md.random_bits = rng.get();
    }
    
    //== Prepare register access index options
    Register<bit<32>,_>(1) reg_cleaning_index;
    RegisterAction<bit<32>, _, bit<32>>(reg_cleaning_index) reg_cleaning_index_rw = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
            val = val + 1;
        }
    };
    action calc_cyclic_index(){
        eg_md.cyclic_index = (bit<8>) reg_cleaning_index_rw.execute(0);
    }
    
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_0_TCP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_0_UDP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_0_Other;   
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_1_TCP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_1_UDP;  
        Hash<bit<8>>(HashAlgorithm_t.CRC32) hash_1_Other;   
       
    action calc_hashed_index_TCP(){
           eg_md.hashed_index_row_0 = hash_0_TCP.get({
               4w2, hdr.ipv4.src_addr,
               4w2, hdr.ipv4.dst_addr,
               4w7, hdr.tcp.src_port,
               5w17, hdr.tcp.dst_port
           });
           eg_md.hashed_index_row_1 = hash_1_TCP.get({
               3w5, hdr.ipv4.src_addr,
               3w4, hdr.ipv4.dst_addr,
               4w6, hdr.tcp.src_port,
               3w2, hdr.tcp.dst_port
           });
    }
    action calc_hashed_index_UDP(){
           eg_md.hashed_index_row_0 = hash_0_UDP.get({
               4w14, hdr.ipv4.src_addr,
               4w1, hdr.ipv4.dst_addr,
               5w3, hdr.udp.src_port,
               3w0, hdr.udp.dst_port
           });
           eg_md.hashed_index_row_1 = hash_1_UDP.get({
               4w0, hdr.ipv4.src_addr,
               4w1, hdr.ipv4.dst_addr,
               5w14, hdr.udp.src_port,
               5w19, hdr.udp.dst_port
           });
    }
    action calc_hashed_index_Other(){
           eg_md.hashed_index_row_0 = hash_0_Other.get({
               4w4, hdr.ipv4.src_addr,
               5w14, hdr.ipv4.dst_addr,
               5w18, hdr.ipv4.protocol
           });
           eg_md.hashed_index_row_1 = hash_1_Other.get({
               3w1, hdr.ipv4.src_addr,
               4w11, hdr.ipv4.dst_addr,
               3w5, hdr.ipv4.protocol
           });
    }
    
    
    //== Deciding on using hashed-based or cyclic-based index
        action snap_0_select_index_hash(){
                eg_md.snap_0_row_0_index=eg_md.cyclic_index;
                eg_md.snap_0_row_1_index=eg_md.cyclic_index;
        }
        action snap_0_select_index_cyclic(){
                eg_md.snap_0_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_0_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_0_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_0_select_index_hash;
                snap_0_select_index_cyclic;
            }
            size = 2;
            default_action = snap_0_select_index_hash();
            const entries = {
               0 : snap_0_select_index_cyclic();
            }
        }
        action snap_1_select_index_hash(){
                eg_md.snap_1_row_0_index=eg_md.cyclic_index;
                eg_md.snap_1_row_1_index=eg_md.cyclic_index;
        }
        action snap_1_select_index_cyclic(){
                eg_md.snap_1_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_1_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_1_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_1_select_index_hash;
                snap_1_select_index_cyclic;
            }
            size = 2;
            default_action = snap_1_select_index_hash();
            const entries = {
               1 : snap_1_select_index_cyclic();
            }
        }
        action snap_2_select_index_hash(){
                eg_md.snap_2_row_0_index=eg_md.cyclic_index;
                eg_md.snap_2_row_1_index=eg_md.cyclic_index;
        }
        action snap_2_select_index_cyclic(){
                eg_md.snap_2_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_2_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_2_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_2_select_index_hash;
                snap_2_select_index_cyclic;
            }
            size = 2;
            default_action = snap_2_select_index_hash();
            const entries = {
               2 : snap_2_select_index_cyclic();
            }
        }
        action snap_3_select_index_hash(){
                eg_md.snap_3_row_0_index=eg_md.cyclic_index;
                eg_md.snap_3_row_1_index=eg_md.cyclic_index;
        }
        action snap_3_select_index_cyclic(){
                eg_md.snap_3_row_0_index=eg_md.hashed_index_row_0;
                eg_md.snap_3_row_1_index=eg_md.hashed_index_row_1;
        }
        table tb_snap_3_select_index {
            key = {
                eg_md.snap_epoch: exact;
            }
            actions = {
                snap_3_select_index_hash;
                snap_3_select_index_cyclic;
            }
            size = 2;
            default_action = snap_3_select_index_hash();
            const entries = {
               3 : snap_3_select_index_cyclic();
            }
        }
    
    
    //== Prepare snapshot register access actions 
            Register<bit<32>,_>(256) snap_0_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_0_row_0_read(){
                eg_md.snap_0_row_0_read=snap_0_row_0_read.execute(eg_md.snap_0_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_0_row_0_inc(){
                eg_md.snap_0_row_0_read=snap_0_row_0_inc.execute(eg_md.snap_0_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_0) snap_0_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_0_row_0_clr(){
                snap_0_row_0_clr.execute(eg_md.snap_0_row_0_index);
            }
            table tb_snap_0_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_0_row_0_read;
                    regexec_snap_0_row_0_inc;
                    regexec_snap_0_row_0_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (0, 0..255) : regexec_snap_0_row_0_clr;
                    (1, 0..255) : regexec_snap_0_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (2, 1..255) : regexec_snap_0_row_0_read;
                        (3, 2..255) : regexec_snap_0_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_0_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_0_row_1_read(){
                eg_md.snap_0_row_1_read=snap_0_row_1_read.execute(eg_md.snap_0_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_0_row_1_inc(){
                eg_md.snap_0_row_1_read=snap_0_row_1_inc.execute(eg_md.snap_0_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_0_row_1) snap_0_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_0_row_1_clr(){
                snap_0_row_1_clr.execute(eg_md.snap_0_row_1_index);
            }
            table tb_snap_0_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_0_row_1_read;
                    regexec_snap_0_row_1_inc;
                    regexec_snap_0_row_1_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (0, 0..255) : regexec_snap_0_row_1_clr;
                    (1, 0..255) : regexec_snap_0_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (2, 1..255) : regexec_snap_0_row_1_read;
                        (3, 2..255) : regexec_snap_0_row_1_read;
                }
            }
            Register<bit<32>,_>(256) snap_1_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_1_row_0_read(){
                eg_md.snap_1_row_0_read=snap_1_row_0_read.execute(eg_md.snap_1_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_1_row_0_inc(){
                eg_md.snap_1_row_0_read=snap_1_row_0_inc.execute(eg_md.snap_1_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_0) snap_1_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_1_row_0_clr(){
                snap_1_row_0_clr.execute(eg_md.snap_1_row_0_index);
            }
            table tb_snap_1_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_1_row_0_read;
                    regexec_snap_1_row_0_inc;
                    regexec_snap_1_row_0_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (1, 0..255) : regexec_snap_1_row_0_clr;
                    (2, 0..255) : regexec_snap_1_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (3, 1..255) : regexec_snap_1_row_0_read;
                        (0, 2..255) : regexec_snap_1_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_1_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_1_row_1_read(){
                eg_md.snap_1_row_1_read=snap_1_row_1_read.execute(eg_md.snap_1_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_1_row_1_inc(){
                eg_md.snap_1_row_1_read=snap_1_row_1_inc.execute(eg_md.snap_1_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_1_row_1) snap_1_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_1_row_1_clr(){
                snap_1_row_1_clr.execute(eg_md.snap_1_row_1_index);
            }
            table tb_snap_1_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_1_row_1_read;
                    regexec_snap_1_row_1_inc;
                    regexec_snap_1_row_1_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (1, 0..255) : regexec_snap_1_row_1_clr;
                    (2, 0..255) : regexec_snap_1_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (3, 1..255) : regexec_snap_1_row_1_read;
                        (0, 2..255) : regexec_snap_1_row_1_read;
                }
            }
            Register<bit<32>,_>(256) snap_2_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_2_row_0_read(){
                eg_md.snap_2_row_0_read=snap_2_row_0_read.execute(eg_md.snap_2_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_2_row_0_inc(){
                eg_md.snap_2_row_0_read=snap_2_row_0_inc.execute(eg_md.snap_2_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_0) snap_2_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_2_row_0_clr(){
                snap_2_row_0_clr.execute(eg_md.snap_2_row_0_index);
            }
            table tb_snap_2_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_2_row_0_read;
                    regexec_snap_2_row_0_inc;
                    regexec_snap_2_row_0_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (2, 0..255) : regexec_snap_2_row_0_clr;
                    (3, 0..255) : regexec_snap_2_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (0, 1..255) : regexec_snap_2_row_0_read;
                        (1, 2..255) : regexec_snap_2_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_2_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_2_row_1_read(){
                eg_md.snap_2_row_1_read=snap_2_row_1_read.execute(eg_md.snap_2_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_2_row_1_inc(){
                eg_md.snap_2_row_1_read=snap_2_row_1_inc.execute(eg_md.snap_2_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_2_row_1) snap_2_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_2_row_1_clr(){
                snap_2_row_1_clr.execute(eg_md.snap_2_row_1_index);
            }
            table tb_snap_2_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_2_row_1_read;
                    regexec_snap_2_row_1_inc;
                    regexec_snap_2_row_1_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (2, 0..255) : regexec_snap_2_row_1_clr;
                    (3, 0..255) : regexec_snap_2_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (0, 1..255) : regexec_snap_2_row_1_read;
                        (1, 2..255) : regexec_snap_2_row_1_read;
                }
            }
            Register<bit<32>,_>(256) snap_3_row_0;
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_3_row_0_read(){
                eg_md.snap_3_row_0_read=snap_3_row_0_read.execute(eg_md.snap_3_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_3_row_0_inc(){
                eg_md.snap_3_row_0_read=snap_3_row_0_inc.execute(eg_md.snap_3_row_0_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_0) snap_3_row_0_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_3_row_0_clr(){
                snap_3_row_0_clr.execute(eg_md.snap_3_row_0_index);
            }
            table tb_snap_3_row_0_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_3_row_0_read;
                    regexec_snap_3_row_0_inc;
                    regexec_snap_3_row_0_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (3, 0..255) : regexec_snap_3_row_0_clr;
                    (0, 0..255) : regexec_snap_3_row_0_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (1, 1..255) : regexec_snap_3_row_0_read;
                        (2, 2..255) : regexec_snap_3_row_0_read;
                }
            }
            Register<bit<32>,_>(256) snap_3_row_1;
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_read = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        rv = val;
                    }
                };
            action regexec_snap_3_row_1_read(){
                eg_md.snap_3_row_1_read=snap_3_row_1_read.execute(eg_md.snap_3_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_inc = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = val + SKETCH_INC;
                        rv = val;
                    }
                };
            action regexec_snap_3_row_1_inc(){
                eg_md.snap_3_row_1_read=snap_3_row_1_inc.execute(eg_md.snap_3_row_1_index);
            }
            RegisterAction<bit<32>, _, bit<32>> (snap_3_row_1) snap_3_row_1_clr = {
                    void apply(inout bit<32> val, out bit<32> rv) {
                        val = 0;
                        rv = 0;
                    }
                };
            action regexec_snap_3_row_1_clr(){
                snap_3_row_1_clr.execute(eg_md.snap_3_row_1_index);
            }
            table tb_snap_3_row_1_rr {
                key = {
                    eg_md.snap_epoch: exact;
                    eg_md.num_snapshots_to_read: range;
                }
                actions = {
                    regexec_snap_3_row_1_read;
                    regexec_snap_3_row_1_inc;
                    regexec_snap_3_row_1_clr;
                    nop;
                }
                size = 17;
                default_action = nop();
                //round-robin logic
                const entries = {
                    (3, 0..255) : regexec_snap_3_row_1_clr;
                    (0, 0..255) : regexec_snap_3_row_1_inc;
                    //read only when qlen/T is large enough (otherwise leave 0)
                        (1, 1..255) : regexec_snap_3_row_1_read;
                        (2, 2..255) : regexec_snap_3_row_1_read;
                }
            }
  
    
    //== Folding sums, which can't be written inline 
            action calc_sum_0_l0(){
                eg_md.snap_0_read_min_l1 = 
                eg_md.snap_0_read_min_l0 + eg_md.snap_1_read_min_l0;
            }
            action calc_sum_2_l0(){
                eg_md.snap_2_read_min_l1 = 
                eg_md.snap_2_read_min_l0 + eg_md.snap_3_read_min_l0;
            }
  
            action calc_sum_0_l1(){
                eg_md.snap_0_read_min_l2 = 
                eg_md.snap_0_read_min_l1 + eg_md.snap_2_read_min_l1;
            }
  
  
    
    //== Finally, actions based on flow size in the queue
    table tb_per_flow_action {
        key = {
            eg_md.snap_0_read_min_l2[26:10]: range; //scale down to 16 bits
            eg_md.q_delay: range;
            eg_md.random_bits: range;
            hdr.ipv4.ecn : exact;
        }
        actions = {
            nop;
            drop;
            mark_ECN;
        }
        default_action = nop();
        // const entries = {  }
    }
    
    apply {
        tb_gatekeeper.apply();
        
        // Startup
        prep_epochs();
        prep_reads();
        prep_random();
        
        // Index for sketch cleaning and read/write
        calc_cyclic_index();
        if(hdr.ipv4.protocol==IP_PROTOCOLS_TCP){
            calc_hashed_index_TCP();
        }else if(hdr.ipv4.protocol==IP_PROTOCOLS_UDP){
            calc_hashed_index_UDP();
        }else{
            calc_hashed_index_Other();
        }
        
        // Select index for snapshots. Cyclic for cleaning, hashed for read/inc
            tb_snap_0_select_index.apply();
            tb_snap_1_select_index.apply();
            tb_snap_2_select_index.apply();
            tb_snap_3_select_index.apply();
   
        
        // Run the snapshots! Round-robin clean, inc, read
                 tb_snap_0_row_0_rr.apply();
                 tb_snap_0_row_1_rr.apply();
                 tb_snap_1_row_0_rr.apply();
                 tb_snap_1_row_1_rr.apply();
                 tb_snap_2_row_0_rr.apply();
                 tb_snap_2_row_1_rr.apply();
                 tb_snap_3_row_0_rr.apply();
                 tb_snap_3_row_1_rr.apply();
   
        
        // Calc min across rows (as in count-"min" sketch)
                eg_md.snap_0_read_min_l0=min(eg_md.snap_0_row_0_read,eg_md.snap_0_row_1_read);
                eg_md.snap_1_read_min_l0=min(eg_md.snap_1_row_0_read,eg_md.snap_1_row_1_read);
                eg_md.snap_2_read_min_l0=min(eg_md.snap_2_row_0_read,eg_md.snap_2_row_1_read);
                eg_md.snap_3_read_min_l0=min(eg_md.snap_3_row_0_read,eg_md.snap_3_row_1_read);
   
        
        // Sum all reads together, using log(CQ_H) layers.
                calc_sum_0_l0();
                calc_sum_2_l0();
  
                calc_sum_0_l1();
  
  
        // bit<32> snap_read_sum=eg_md.snap_0_read_min_l2;
        
        // With flow size in queue, can check for bursty flow and add AQM.
        tb_per_flow_action.apply();
    }
}


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;