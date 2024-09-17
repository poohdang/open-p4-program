// vim: syntax=P4
/*
	BeauCoup: Multiple distinct queries via coupon collectors
	
	Copyright (C) 2019 Xiaoqi Chen, Princeton University
    xiaoqic [at] cs.princeton.edu
    
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

#define DECAY_TIME_WINDOW (100*1000*1000)
//Default table entry expiry timeout: 100ms

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
    bit<8> diffserv;
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


//== Metadata definition: one set of variables for each hash function

struct ig_metadata_t {
    // hash function activations
    bit<16> h_1;				// the value of h(attr)
    bit<1> h_1_activated; 	// if there's any coupon activated
    bit<4> h_1_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_1_qid;			// the query id activated			
    bit<8> h_1_cid;			// the coupon id activated
    bit<8> h_1_ctotal;		// number of coupons required for sending alert
    bit<16> h_2;				// the value of h(attr)
    bit<1> h_2_activated; 	// if there's any coupon activated
    bit<4> h_2_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_2_qid;			// the query id activated			
    bit<8> h_2_cid;			// the coupon id activated
    bit<8> h_2_ctotal;		// number of coupons required for sending alert
    bit<16> h_3;				// the value of h(attr)
    bit<1> h_3_activated; 	// if there's any coupon activated
    bit<4> h_3_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_3_qid;			// the query id activated			
    bit<8> h_3_cid;			// the coupon id activated
    bit<8> h_3_ctotal;		// number of coupons required for sending alert
    bit<16> h_4;				// the value of h(attr)
    bit<1> h_4_activated; 	// if there's any coupon activated
    bit<4> h_4_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_4_qid;			// the query id activated			
    bit<8> h_4_cid;			// the coupon id activated
    bit<8> h_4_ctotal;		// number of coupons required for sending alert
    bit<16> h_5;				// the value of h(attr)
    bit<1> h_5_activated; 	// if there's any coupon activated
    bit<4> h_5_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_5_qid;			// the query id activated			
    bit<8> h_5_cid;			// the coupon id activated
    bit<8> h_5_ctotal;		// number of coupons required for sending alert
    bit<16> h_6;				// the value of h(attr)
    bit<1> h_6_activated; 	// if there's any coupon activated
    bit<4> h_6_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_6_qid;			// the query id activated			
    bit<8> h_6_cid;			// the coupon id activated
    bit<8> h_6_ctotal;		// number of coupons required for sending alert
    bit<16> h_7;				// the value of h(attr)
    bit<1> h_7_activated; 	// if there's any coupon activated
    bit<4> h_7_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_7_qid;			// the query id activated			
    bit<8> h_7_cid;			// the coupon id activated
    bit<8> h_7_ctotal;		// number of coupons required for sending alert
    bit<16> h_8;				// the value of h(attr)
    bit<1> h_8_activated; 	// if there's any coupon activated
    bit<4> h_8_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_8_qid;			// the query id activated			
    bit<8> h_8_cid;			// the coupon id activated
    bit<8> h_8_ctotal;		// number of coupons required for sending alert
    bit<16> h_9;				// the value of h(attr)
    bit<1> h_9_activated; 	// if there's any coupon activated
    bit<4> h_9_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_9_qid;			// the query id activated			
    bit<8> h_9_cid;			// the coupon id activated
    bit<8> h_9_ctotal;		// number of coupons required for sending alert
    bit<16> h_10;				// the value of h(attr)
    bit<1> h_10_activated; 	// if there's any coupon activated
    bit<4> h_10_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_10_qid;			// the query id activated			
    bit<8> h_10_cid;			// the coupon id activated
    bit<8> h_10_ctotal;		// number of coupons required for sending alert
    bit<16> h_11;				// the value of h(attr)
    bit<1> h_11_activated; 	// if there's any coupon activated
    bit<4> h_11_keydefn;		// the key definition id (later used for reconstructing key)
    bit<8> h_11_qid;			// the query id activated			
    bit<8> h_11_cid;			// the coupon id activated
    bit<8> h_11_ctotal;		// number of coupons required for sending alert
 
    bit<1> random_1_bit;

    // after tie breaking, one coupon gets selected
    bit<1> h_s_activated;
    bit<4> h_s_keydefn;
    bit<8> h_s_qid;
    bit<8> h_s_cid;
    bit<8> h_s_ctotal;
    
    //exctracting flow key
    bit<32> key_p1;
    bit<32> key_p2;
    bit<16> key_p3;
    bit<16> key_p4;
    bit<32> key_sig;
    bit<16> key_loc;


    // decay gatekeeper related
    bit<32> current_timestamp;
    bit<1> cf_decay_has_expired;
    // key check
    bit<1> cf_key_matched;

    // coupon operator related
    bit<32> coupon_onehot;
    bit<32> coupon_merge_check;
    bit<8> coupon_total_activated;

}
struct eg_metadata_t {
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
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
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

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
         
    //Resubmit() resubmit;
    
    apply {        
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
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
       
        action route_to_64(){
            //route to CPU NIC. on model, it is veth250
            ig_intr_tm_md.ucast_egress_port=64;
        }
        action reflect(){
            //send you back to where you're from
            ig_intr_tm_md.ucast_egress_port=ig_intr_md.ingress_port;
        }
        
        // ======== Section 1: use hash to activate coupons

        // hash function definitions
        
        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1;
        action calc_hash_1_a(){
            ig_md.h_1 = hash_1.get({  16w19135,8w0,  ig_intr_md.ingress_mac_tstamp   });    
        }
        
        action set_h_1_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_1_activated=1;
            ig_md.h_1_cid=cid;
            ig_md.h_1_qid=qid;
            ig_md.h_1_ctotal=ctot;
            ig_md.h_1_keydefn=kdf;
        }
        action set_h_1_no_match(){
            ig_md.h_1_activated=0;
        }
        
        table tb_activate_coupons_h_1_ {
            key = {
                ig_md.h_1: range;
            }
            actions = {
                set_h_1_matched;
                set_h_1_no_match;
            }
            default_action = set_h_1_no_match();
            const entries = {
                    0 .. 15 : set_h_1_matched(0,25,23,12);
                    16 .. 31 : set_h_1_matched(1,25,23,12);
                    32 .. 47 : set_h_1_matched(2,25,23,12);
                    48 .. 63 : set_h_1_matched(3,25,23,12);
                    64 .. 79 : set_h_1_matched(4,25,23,12);
                    80 .. 95 : set_h_1_matched(5,25,23,12);
                    96 .. 111 : set_h_1_matched(6,25,23,12);
                    112 .. 127 : set_h_1_matched(7,25,23,12);
                    128 .. 143 : set_h_1_matched(8,25,23,12);
                    144 .. 159 : set_h_1_matched(9,25,23,12);
                    160 .. 175 : set_h_1_matched(10,25,23,12);
                    176 .. 191 : set_h_1_matched(11,25,23,12);
                    192 .. 207 : set_h_1_matched(12,25,23,12);
                    208 .. 223 : set_h_1_matched(13,25,23,12);
                    224 .. 239 : set_h_1_matched(14,25,23,12);
                    240 .. 255 : set_h_1_matched(15,25,23,12);
                    256 .. 271 : set_h_1_matched(16,25,23,12);
                    272 .. 287 : set_h_1_matched(17,25,23,12);
                    288 .. 303 : set_h_1_matched(18,25,23,12);
                    304 .. 319 : set_h_1_matched(19,25,23,12);
                    320 .. 335 : set_h_1_matched(20,25,23,12);
                    336 .. 351 : set_h_1_matched(21,25,23,12);
                    352 .. 367 : set_h_1_matched(22,25,23,12);
                    368 .. 383 : set_h_1_matched(23,25,23,12);
                    384 .. 399 : set_h_1_matched(24,25,23,12);
                    400 .. 415 : set_h_1_matched(25,25,23,12);
                    416 .. 431 : set_h_1_matched(26,25,23,12);
                    432 .. 447 : set_h_1_matched(27,25,23,12);
                    448 .. 463 : set_h_1_matched(28,25,23,12);
                    464 .. 479 : set_h_1_matched(29,25,23,12);
                    480 .. 495 : set_h_1_matched(30,25,23,12);
                    496 .. 511 : set_h_1_matched(31,25,23,12);
                    512 .. 519 : set_h_1_matched(0,1,23,2);
                    520 .. 527 : set_h_1_matched(1,1,23,2);
                    528 .. 535 : set_h_1_matched(2,1,23,2);
                    536 .. 543 : set_h_1_matched(3,1,23,2);
                    544 .. 551 : set_h_1_matched(4,1,23,2);
                    552 .. 559 : set_h_1_matched(5,1,23,2);
                    560 .. 567 : set_h_1_matched(6,1,23,2);
                    568 .. 575 : set_h_1_matched(7,1,23,2);
                    576 .. 583 : set_h_1_matched(8,1,23,2);
                    584 .. 591 : set_h_1_matched(9,1,23,2);
                    592 .. 599 : set_h_1_matched(10,1,23,2);
                    600 .. 607 : set_h_1_matched(11,1,23,2);
                    608 .. 615 : set_h_1_matched(12,1,23,2);
                    616 .. 623 : set_h_1_matched(13,1,23,2);
                    624 .. 631 : set_h_1_matched(14,1,23,2);
                    632 .. 639 : set_h_1_matched(15,1,23,2);
                    640 .. 647 : set_h_1_matched(16,1,23,2);
                    648 .. 655 : set_h_1_matched(17,1,23,2);
                    656 .. 663 : set_h_1_matched(18,1,23,2);
                    664 .. 671 : set_h_1_matched(19,1,23,2);
                    672 .. 679 : set_h_1_matched(20,1,23,2);
                    680 .. 687 : set_h_1_matched(21,1,23,2);
                    688 .. 695 : set_h_1_matched(22,1,23,2);
                    696 .. 703 : set_h_1_matched(23,1,23,2);
                    704 .. 711 : set_h_1_matched(24,1,23,2);
                    712 .. 719 : set_h_1_matched(25,1,23,2);
                    720 .. 727 : set_h_1_matched(26,1,23,2);
                    728 .. 735 : set_h_1_matched(27,1,23,2);
                    736 .. 743 : set_h_1_matched(28,1,23,2);
                    744 .. 751 : set_h_1_matched(29,1,23,2);
                    752 .. 759 : set_h_1_matched(30,1,23,2);
                    760 .. 767 : set_h_1_matched(31,1,23,2);
                    768 .. 775 : set_h_1_matched(0,24,23,3);
                    776 .. 783 : set_h_1_matched(1,24,23,3);
                    784 .. 791 : set_h_1_matched(2,24,23,3);
                    792 .. 799 : set_h_1_matched(3,24,23,3);
                    800 .. 807 : set_h_1_matched(4,24,23,3);
                    808 .. 815 : set_h_1_matched(5,24,23,3);
                    816 .. 823 : set_h_1_matched(6,24,23,3);
                    824 .. 831 : set_h_1_matched(7,24,23,3);
                    832 .. 839 : set_h_1_matched(8,24,23,3);
                    840 .. 847 : set_h_1_matched(9,24,23,3);
                    848 .. 855 : set_h_1_matched(10,24,23,3);
                    856 .. 863 : set_h_1_matched(11,24,23,3);
                    864 .. 871 : set_h_1_matched(12,24,23,3);
                    872 .. 879 : set_h_1_matched(13,24,23,3);
                    880 .. 887 : set_h_1_matched(14,24,23,3);
                    888 .. 895 : set_h_1_matched(15,24,23,3);
                    896 .. 903 : set_h_1_matched(16,24,23,3);
                    904 .. 911 : set_h_1_matched(17,24,23,3);
                    912 .. 919 : set_h_1_matched(18,24,23,3);
                    920 .. 927 : set_h_1_matched(19,24,23,3);
                    928 .. 935 : set_h_1_matched(20,24,23,3);
                    936 .. 943 : set_h_1_matched(21,24,23,3);
                    944 .. 951 : set_h_1_matched(22,24,23,3);
                    952 .. 959 : set_h_1_matched(23,24,23,3);
                    960 .. 967 : set_h_1_matched(24,24,23,3);
                    968 .. 975 : set_h_1_matched(25,24,23,3);
                    976 .. 983 : set_h_1_matched(26,24,23,3);
                    984 .. 991 : set_h_1_matched(27,24,23,3);
                    992 .. 999 : set_h_1_matched(28,24,23,3);
                    1000 .. 1007 : set_h_1_matched(29,24,23,3);
                    1008 .. 1015 : set_h_1_matched(30,24,23,3);
                    1016 .. 1023 : set_h_1_matched(31,24,23,3);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_2;
        action calc_hash_2_a(){
            ig_md.h_2 = hash_2.get({  16w57809,7w0,  hdr.ipv4.dst_addr   });    
        }
        
        action set_h_2_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_2_activated=1;
            ig_md.h_2_cid=cid;
            ig_md.h_2_qid=qid;
            ig_md.h_2_ctotal=ctot;
            ig_md.h_2_keydefn=kdf;
        }
        action set_h_2_no_match(){
            ig_md.h_2_activated=0;
        }
        
        table tb_activate_coupons_h_2_ {
            key = {
                ig_md.h_2: range;
            }
            actions = {
                set_h_2_matched;
                set_h_2_no_match;
            }
            default_action = set_h_2_no_match();
            const entries = {
                    0 .. 63 : set_h_2_matched(0,0,20,1);
                    64 .. 127 : set_h_2_matched(1,0,20,1);
                    128 .. 191 : set_h_2_matched(2,0,20,1);
                    192 .. 255 : set_h_2_matched(3,0,20,1);
                    256 .. 319 : set_h_2_matched(4,0,20,1);
                    320 .. 383 : set_h_2_matched(5,0,20,1);
                    384 .. 447 : set_h_2_matched(6,0,20,1);
                    448 .. 511 : set_h_2_matched(7,0,20,1);
                    512 .. 575 : set_h_2_matched(8,0,20,1);
                    576 .. 639 : set_h_2_matched(9,0,20,1);
                    640 .. 703 : set_h_2_matched(10,0,20,1);
                    704 .. 767 : set_h_2_matched(11,0,20,1);
                    768 .. 831 : set_h_2_matched(12,0,20,1);
                    832 .. 895 : set_h_2_matched(13,0,20,1);
                    896 .. 959 : set_h_2_matched(14,0,20,1);
                    960 .. 1023 : set_h_2_matched(15,0,20,1);
                    1024 .. 1087 : set_h_2_matched(16,0,20,1);
                    1088 .. 1151 : set_h_2_matched(17,0,20,1);
                    1152 .. 1215 : set_h_2_matched(18,0,20,1);
                    1216 .. 1279 : set_h_2_matched(19,0,20,1);
                    1280 .. 1343 : set_h_2_matched(20,0,20,1);
                    1344 .. 1407 : set_h_2_matched(21,0,20,1);
                    1408 .. 1471 : set_h_2_matched(22,0,20,1);
                    1472 .. 1535 : set_h_2_matched(23,0,20,1);
                    1536 .. 1599 : set_h_2_matched(24,0,20,1);
                    1600 .. 1663 : set_h_2_matched(25,0,20,1);
                    1664 .. 1727 : set_h_2_matched(26,0,20,1);
                    1728 .. 1791 : set_h_2_matched(27,0,20,1);
                    1792 .. 1855 : set_h_2_matched(28,0,20,1);
                    1856 .. 1919 : set_h_2_matched(29,0,20,1);
                    1920 .. 1983 : set_h_2_matched(30,0,20,1);
                    1984 .. 2047 : set_h_2_matched(31,0,20,1);
                    2048 .. 2111 : set_h_2_matched(0,6,20,1);
                    2112 .. 2175 : set_h_2_matched(1,6,20,1);
                    2176 .. 2239 : set_h_2_matched(2,6,20,1);
                    2240 .. 2303 : set_h_2_matched(3,6,20,1);
                    2304 .. 2367 : set_h_2_matched(4,6,20,1);
                    2368 .. 2431 : set_h_2_matched(5,6,20,1);
                    2432 .. 2495 : set_h_2_matched(6,6,20,1);
                    2496 .. 2559 : set_h_2_matched(7,6,20,1);
                    2560 .. 2623 : set_h_2_matched(8,6,20,1);
                    2624 .. 2687 : set_h_2_matched(9,6,20,1);
                    2688 .. 2751 : set_h_2_matched(10,6,20,1);
                    2752 .. 2815 : set_h_2_matched(11,6,20,1);
                    2816 .. 2879 : set_h_2_matched(12,6,20,1);
                    2880 .. 2943 : set_h_2_matched(13,6,20,1);
                    2944 .. 3007 : set_h_2_matched(14,6,20,1);
                    3008 .. 3071 : set_h_2_matched(15,6,20,1);
                    3072 .. 3135 : set_h_2_matched(16,6,20,1);
                    3136 .. 3199 : set_h_2_matched(17,6,20,1);
                    3200 .. 3263 : set_h_2_matched(18,6,20,1);
                    3264 .. 3327 : set_h_2_matched(19,6,20,1);
                    3328 .. 3391 : set_h_2_matched(20,6,20,1);
                    3392 .. 3455 : set_h_2_matched(21,6,20,1);
                    3456 .. 3519 : set_h_2_matched(22,6,20,1);
                    3520 .. 3583 : set_h_2_matched(23,6,20,1);
                    3584 .. 3647 : set_h_2_matched(24,6,20,1);
                    3648 .. 3711 : set_h_2_matched(25,6,20,1);
                    3712 .. 3775 : set_h_2_matched(26,6,20,1);
                    3776 .. 3839 : set_h_2_matched(27,6,20,1);
                    3840 .. 3903 : set_h_2_matched(28,6,20,1);
                    3904 .. 3967 : set_h_2_matched(29,6,20,1);
                    3968 .. 4031 : set_h_2_matched(30,6,20,1);
                    4032 .. 4095 : set_h_2_matched(31,6,20,1);
                    4096 .. 4159 : set_h_2_matched(0,8,20,5);
                    4160 .. 4223 : set_h_2_matched(1,8,20,5);
                    4224 .. 4287 : set_h_2_matched(2,8,20,5);
                    4288 .. 4351 : set_h_2_matched(3,8,20,5);
                    4352 .. 4415 : set_h_2_matched(4,8,20,5);
                    4416 .. 4479 : set_h_2_matched(5,8,20,5);
                    4480 .. 4543 : set_h_2_matched(6,8,20,5);
                    4544 .. 4607 : set_h_2_matched(7,8,20,5);
                    4608 .. 4671 : set_h_2_matched(8,8,20,5);
                    4672 .. 4735 : set_h_2_matched(9,8,20,5);
                    4736 .. 4799 : set_h_2_matched(10,8,20,5);
                    4800 .. 4863 : set_h_2_matched(11,8,20,5);
                    4864 .. 4927 : set_h_2_matched(12,8,20,5);
                    4928 .. 4991 : set_h_2_matched(13,8,20,5);
                    4992 .. 5055 : set_h_2_matched(14,8,20,5);
                    5056 .. 5119 : set_h_2_matched(15,8,20,5);
                    5120 .. 5183 : set_h_2_matched(16,8,20,5);
                    5184 .. 5247 : set_h_2_matched(17,8,20,5);
                    5248 .. 5311 : set_h_2_matched(18,8,20,5);
                    5312 .. 5375 : set_h_2_matched(19,8,20,5);
                    5376 .. 5439 : set_h_2_matched(20,8,20,5);
                    5440 .. 5503 : set_h_2_matched(21,8,20,5);
                    5504 .. 5567 : set_h_2_matched(22,8,20,5);
                    5568 .. 5631 : set_h_2_matched(23,8,20,5);
                    5632 .. 5695 : set_h_2_matched(24,8,20,5);
                    5696 .. 5759 : set_h_2_matched(25,8,20,5);
                    5760 .. 5823 : set_h_2_matched(26,8,20,5);
                    5824 .. 5887 : set_h_2_matched(27,8,20,5);
                    5888 .. 5951 : set_h_2_matched(28,8,20,5);
                    5952 .. 6015 : set_h_2_matched(29,8,20,5);
                    6016 .. 6079 : set_h_2_matched(30,8,20,5);
                    6080 .. 6143 : set_h_2_matched(31,8,20,5);
                    6144 .. 6207 : set_h_2_matched(0,15,20,6);
                    6208 .. 6271 : set_h_2_matched(1,15,20,6);
                    6272 .. 6335 : set_h_2_matched(2,15,20,6);
                    6336 .. 6399 : set_h_2_matched(3,15,20,6);
                    6400 .. 6463 : set_h_2_matched(4,15,20,6);
                    6464 .. 6527 : set_h_2_matched(5,15,20,6);
                    6528 .. 6591 : set_h_2_matched(6,15,20,6);
                    6592 .. 6655 : set_h_2_matched(7,15,20,6);
                    6656 .. 6719 : set_h_2_matched(8,15,20,6);
                    6720 .. 6783 : set_h_2_matched(9,15,20,6);
                    6784 .. 6847 : set_h_2_matched(10,15,20,6);
                    6848 .. 6911 : set_h_2_matched(11,15,20,6);
                    6912 .. 6975 : set_h_2_matched(12,15,20,6);
                    6976 .. 7039 : set_h_2_matched(13,15,20,6);
                    7040 .. 7103 : set_h_2_matched(14,15,20,6);
                    7104 .. 7167 : set_h_2_matched(15,15,20,6);
                    7168 .. 7231 : set_h_2_matched(16,15,20,6);
                    7232 .. 7295 : set_h_2_matched(17,15,20,6);
                    7296 .. 7359 : set_h_2_matched(18,15,20,6);
                    7360 .. 7423 : set_h_2_matched(19,15,20,6);
                    7424 .. 7487 : set_h_2_matched(20,15,20,6);
                    7488 .. 7551 : set_h_2_matched(21,15,20,6);
                    7552 .. 7615 : set_h_2_matched(22,15,20,6);
                    7616 .. 7679 : set_h_2_matched(23,15,20,6);
                    7680 .. 7743 : set_h_2_matched(24,15,20,6);
                    7744 .. 7807 : set_h_2_matched(25,15,20,6);
                    7808 .. 7871 : set_h_2_matched(26,15,20,6);
                    7872 .. 7935 : set_h_2_matched(27,15,20,6);
                    7936 .. 7999 : set_h_2_matched(28,15,20,6);
                    8000 .. 8063 : set_h_2_matched(29,15,20,6);
                    8064 .. 8127 : set_h_2_matched(30,15,20,6);
                    8128 .. 8191 : set_h_2_matched(31,15,20,6);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_3;
        action calc_hash_3_a(){
            ig_md.h_3 = hash_3.get({  16w31382,15w0,  hdr.ipv4.dst_addr,hdr.tcp.dst_port   });    
        }
        
        action set_h_3_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_3_activated=1;
            ig_md.h_3_cid=cid;
            ig_md.h_3_qid=qid;
            ig_md.h_3_ctotal=ctot;
            ig_md.h_3_keydefn=kdf;
        }
        action set_h_3_no_match(){
            ig_md.h_3_activated=0;
        }
        
        table tb_activate_coupons_h_3_ {
            key = {
                ig_md.h_3: range;
            }
            actions = {
                set_h_3_matched;
                set_h_3_no_match;
            }
            default_action = set_h_3_no_match();
            const entries = {
                    0 .. 63 : set_h_3_matched(0,7,20,1);
                    64 .. 127 : set_h_3_matched(1,7,20,1);
                    128 .. 191 : set_h_3_matched(2,7,20,1);
                    192 .. 255 : set_h_3_matched(3,7,20,1);
                    256 .. 319 : set_h_3_matched(4,7,20,1);
                    320 .. 383 : set_h_3_matched(5,7,20,1);
                    384 .. 447 : set_h_3_matched(6,7,20,1);
                    448 .. 511 : set_h_3_matched(7,7,20,1);
                    512 .. 575 : set_h_3_matched(8,7,20,1);
                    576 .. 639 : set_h_3_matched(9,7,20,1);
                    640 .. 703 : set_h_3_matched(10,7,20,1);
                    704 .. 767 : set_h_3_matched(11,7,20,1);
                    768 .. 831 : set_h_3_matched(12,7,20,1);
                    832 .. 895 : set_h_3_matched(13,7,20,1);
                    896 .. 959 : set_h_3_matched(14,7,20,1);
                    960 .. 1023 : set_h_3_matched(15,7,20,1);
                    1024 .. 1087 : set_h_3_matched(16,7,20,1);
                    1088 .. 1151 : set_h_3_matched(17,7,20,1);
                    1152 .. 1215 : set_h_3_matched(18,7,20,1);
                    1216 .. 1279 : set_h_3_matched(19,7,20,1);
                    1280 .. 1343 : set_h_3_matched(20,7,20,1);
                    1344 .. 1407 : set_h_3_matched(21,7,20,1);
                    1408 .. 1471 : set_h_3_matched(22,7,20,1);
                    1472 .. 1535 : set_h_3_matched(23,7,20,1);
                    1536 .. 1599 : set_h_3_matched(24,7,20,1);
                    1600 .. 1663 : set_h_3_matched(25,7,20,1);
                    1664 .. 1727 : set_h_3_matched(26,7,20,1);
                    1728 .. 1791 : set_h_3_matched(27,7,20,1);
                    1792 .. 1855 : set_h_3_matched(28,7,20,1);
                    1856 .. 1919 : set_h_3_matched(29,7,20,1);
                    1920 .. 1983 : set_h_3_matched(30,7,20,1);
                    1984 .. 2047 : set_h_3_matched(31,7,20,1);
                    2048 .. 2111 : set_h_3_matched(0,9,20,5);
                    2112 .. 2175 : set_h_3_matched(1,9,20,5);
                    2176 .. 2239 : set_h_3_matched(2,9,20,5);
                    2240 .. 2303 : set_h_3_matched(3,9,20,5);
                    2304 .. 2367 : set_h_3_matched(4,9,20,5);
                    2368 .. 2431 : set_h_3_matched(5,9,20,5);
                    2432 .. 2495 : set_h_3_matched(6,9,20,5);
                    2496 .. 2559 : set_h_3_matched(7,9,20,5);
                    2560 .. 2623 : set_h_3_matched(8,9,20,5);
                    2624 .. 2687 : set_h_3_matched(9,9,20,5);
                    2688 .. 2751 : set_h_3_matched(10,9,20,5);
                    2752 .. 2815 : set_h_3_matched(11,9,20,5);
                    2816 .. 2879 : set_h_3_matched(12,9,20,5);
                    2880 .. 2943 : set_h_3_matched(13,9,20,5);
                    2944 .. 3007 : set_h_3_matched(14,9,20,5);
                    3008 .. 3071 : set_h_3_matched(15,9,20,5);
                    3072 .. 3135 : set_h_3_matched(16,9,20,5);
                    3136 .. 3199 : set_h_3_matched(17,9,20,5);
                    3200 .. 3263 : set_h_3_matched(18,9,20,5);
                    3264 .. 3327 : set_h_3_matched(19,9,20,5);
                    3328 .. 3391 : set_h_3_matched(20,9,20,5);
                    3392 .. 3455 : set_h_3_matched(21,9,20,5);
                    3456 .. 3519 : set_h_3_matched(22,9,20,5);
                    3520 .. 3583 : set_h_3_matched(23,9,20,5);
                    3584 .. 3647 : set_h_3_matched(24,9,20,5);
                    3648 .. 3711 : set_h_3_matched(25,9,20,5);
                    3712 .. 3775 : set_h_3_matched(26,9,20,5);
                    3776 .. 3839 : set_h_3_matched(27,9,20,5);
                    3840 .. 3903 : set_h_3_matched(28,9,20,5);
                    3904 .. 3967 : set_h_3_matched(29,9,20,5);
                    3968 .. 4031 : set_h_3_matched(30,9,20,5);
                    4032 .. 4095 : set_h_3_matched(31,9,20,5);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_4;
        action calc_hash_4_a(){
            ig_md.h_4 = hash_4.get({  16w13110,6w0,  hdr.ipv4.dst_addr,hdr.udp.dst_port   });    
        }
        
        action set_h_4_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_4_activated=1;
            ig_md.h_4_cid=cid;
            ig_md.h_4_qid=qid;
            ig_md.h_4_ctotal=ctot;
            ig_md.h_4_keydefn=kdf;
        }
        action set_h_4_no_match(){
            ig_md.h_4_activated=0;
        }
        
        table tb_activate_coupons_h_4_ {
            key = {
                ig_md.h_4: range;
            }
            actions = {
                set_h_4_matched;
                set_h_4_no_match;
            }
            default_action = set_h_4_no_match();
            const entries = {
                    0 .. 63 : set_h_4_matched(0,14,20,1);
                    64 .. 127 : set_h_4_matched(1,14,20,1);
                    128 .. 191 : set_h_4_matched(2,14,20,1);
                    192 .. 255 : set_h_4_matched(3,14,20,1);
                    256 .. 319 : set_h_4_matched(4,14,20,1);
                    320 .. 383 : set_h_4_matched(5,14,20,1);
                    384 .. 447 : set_h_4_matched(6,14,20,1);
                    448 .. 511 : set_h_4_matched(7,14,20,1);
                    512 .. 575 : set_h_4_matched(8,14,20,1);
                    576 .. 639 : set_h_4_matched(9,14,20,1);
                    640 .. 703 : set_h_4_matched(10,14,20,1);
                    704 .. 767 : set_h_4_matched(11,14,20,1);
                    768 .. 831 : set_h_4_matched(12,14,20,1);
                    832 .. 895 : set_h_4_matched(13,14,20,1);
                    896 .. 959 : set_h_4_matched(14,14,20,1);
                    960 .. 1023 : set_h_4_matched(15,14,20,1);
                    1024 .. 1087 : set_h_4_matched(16,14,20,1);
                    1088 .. 1151 : set_h_4_matched(17,14,20,1);
                    1152 .. 1215 : set_h_4_matched(18,14,20,1);
                    1216 .. 1279 : set_h_4_matched(19,14,20,1);
                    1280 .. 1343 : set_h_4_matched(20,14,20,1);
                    1344 .. 1407 : set_h_4_matched(21,14,20,1);
                    1408 .. 1471 : set_h_4_matched(22,14,20,1);
                    1472 .. 1535 : set_h_4_matched(23,14,20,1);
                    1536 .. 1599 : set_h_4_matched(24,14,20,1);
                    1600 .. 1663 : set_h_4_matched(25,14,20,1);
                    1664 .. 1727 : set_h_4_matched(26,14,20,1);
                    1728 .. 1791 : set_h_4_matched(27,14,20,1);
                    1792 .. 1855 : set_h_4_matched(28,14,20,1);
                    1856 .. 1919 : set_h_4_matched(29,14,20,1);
                    1920 .. 1983 : set_h_4_matched(30,14,20,1);
                    1984 .. 2047 : set_h_4_matched(31,14,20,1);
                    2048 .. 2111 : set_h_4_matched(0,16,20,6);
                    2112 .. 2175 : set_h_4_matched(1,16,20,6);
                    2176 .. 2239 : set_h_4_matched(2,16,20,6);
                    2240 .. 2303 : set_h_4_matched(3,16,20,6);
                    2304 .. 2367 : set_h_4_matched(4,16,20,6);
                    2368 .. 2431 : set_h_4_matched(5,16,20,6);
                    2432 .. 2495 : set_h_4_matched(6,16,20,6);
                    2496 .. 2559 : set_h_4_matched(7,16,20,6);
                    2560 .. 2623 : set_h_4_matched(8,16,20,6);
                    2624 .. 2687 : set_h_4_matched(9,16,20,6);
                    2688 .. 2751 : set_h_4_matched(10,16,20,6);
                    2752 .. 2815 : set_h_4_matched(11,16,20,6);
                    2816 .. 2879 : set_h_4_matched(12,16,20,6);
                    2880 .. 2943 : set_h_4_matched(13,16,20,6);
                    2944 .. 3007 : set_h_4_matched(14,16,20,6);
                    3008 .. 3071 : set_h_4_matched(15,16,20,6);
                    3072 .. 3135 : set_h_4_matched(16,16,20,6);
                    3136 .. 3199 : set_h_4_matched(17,16,20,6);
                    3200 .. 3263 : set_h_4_matched(18,16,20,6);
                    3264 .. 3327 : set_h_4_matched(19,16,20,6);
                    3328 .. 3391 : set_h_4_matched(20,16,20,6);
                    3392 .. 3455 : set_h_4_matched(21,16,20,6);
                    3456 .. 3519 : set_h_4_matched(22,16,20,6);
                    3520 .. 3583 : set_h_4_matched(23,16,20,6);
                    3584 .. 3647 : set_h_4_matched(24,16,20,6);
                    3648 .. 3711 : set_h_4_matched(25,16,20,6);
                    3712 .. 3775 : set_h_4_matched(26,16,20,6);
                    3776 .. 3839 : set_h_4_matched(27,16,20,6);
                    3840 .. 3903 : set_h_4_matched(28,16,20,6);
                    3904 .. 3967 : set_h_4_matched(29,16,20,6);
                    3968 .. 4031 : set_h_4_matched(30,16,20,6);
                    4032 .. 4095 : set_h_4_matched(31,16,20,6);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_5;
        action calc_hash_5_a(){
            ig_md.h_5 = hash_5.get({  16w39997,16w0,  hdr.ipv4.src_addr   });    
        }
        
        action set_h_5_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_5_activated=1;
            ig_md.h_5_cid=cid;
            ig_md.h_5_qid=qid;
            ig_md.h_5_ctotal=ctot;
            ig_md.h_5_keydefn=kdf;
        }
        action set_h_5_no_match(){
            ig_md.h_5_activated=0;
        }
        
        table tb_activate_coupons_h_5_ {
            key = {
                ig_md.h_5: range;
            }
            actions = {
                set_h_5_matched;
                set_h_5_no_match;
            }
            default_action = set_h_5_no_match();
            const entries = {
                    0 .. 63 : set_h_5_matched(0,10,20,4);
                    64 .. 127 : set_h_5_matched(1,10,20,4);
                    128 .. 191 : set_h_5_matched(2,10,20,4);
                    192 .. 255 : set_h_5_matched(3,10,20,4);
                    256 .. 319 : set_h_5_matched(4,10,20,4);
                    320 .. 383 : set_h_5_matched(5,10,20,4);
                    384 .. 447 : set_h_5_matched(6,10,20,4);
                    448 .. 511 : set_h_5_matched(7,10,20,4);
                    512 .. 575 : set_h_5_matched(8,10,20,4);
                    576 .. 639 : set_h_5_matched(9,10,20,4);
                    640 .. 703 : set_h_5_matched(10,10,20,4);
                    704 .. 767 : set_h_5_matched(11,10,20,4);
                    768 .. 831 : set_h_5_matched(12,10,20,4);
                    832 .. 895 : set_h_5_matched(13,10,20,4);
                    896 .. 959 : set_h_5_matched(14,10,20,4);
                    960 .. 1023 : set_h_5_matched(15,10,20,4);
                    1024 .. 1087 : set_h_5_matched(16,10,20,4);
                    1088 .. 1151 : set_h_5_matched(17,10,20,4);
                    1152 .. 1215 : set_h_5_matched(18,10,20,4);
                    1216 .. 1279 : set_h_5_matched(19,10,20,4);
                    1280 .. 1343 : set_h_5_matched(20,10,20,4);
                    1344 .. 1407 : set_h_5_matched(21,10,20,4);
                    1408 .. 1471 : set_h_5_matched(22,10,20,4);
                    1472 .. 1535 : set_h_5_matched(23,10,20,4);
                    1536 .. 1599 : set_h_5_matched(24,10,20,4);
                    1600 .. 1663 : set_h_5_matched(25,10,20,4);
                    1664 .. 1727 : set_h_5_matched(26,10,20,4);
                    1728 .. 1791 : set_h_5_matched(27,10,20,4);
                    1792 .. 1855 : set_h_5_matched(28,10,20,4);
                    1856 .. 1919 : set_h_5_matched(29,10,20,4);
                    1920 .. 1983 : set_h_5_matched(30,10,20,4);
                    1984 .. 2047 : set_h_5_matched(31,10,20,4);
                    2048 .. 2111 : set_h_5_matched(0,12,20,2);
                    2112 .. 2175 : set_h_5_matched(1,12,20,2);
                    2176 .. 2239 : set_h_5_matched(2,12,20,2);
                    2240 .. 2303 : set_h_5_matched(3,12,20,2);
                    2304 .. 2367 : set_h_5_matched(4,12,20,2);
                    2368 .. 2431 : set_h_5_matched(5,12,20,2);
                    2432 .. 2495 : set_h_5_matched(6,12,20,2);
                    2496 .. 2559 : set_h_5_matched(7,12,20,2);
                    2560 .. 2623 : set_h_5_matched(8,12,20,2);
                    2624 .. 2687 : set_h_5_matched(9,12,20,2);
                    2688 .. 2751 : set_h_5_matched(10,12,20,2);
                    2752 .. 2815 : set_h_5_matched(11,12,20,2);
                    2816 .. 2879 : set_h_5_matched(12,12,20,2);
                    2880 .. 2943 : set_h_5_matched(13,12,20,2);
                    2944 .. 3007 : set_h_5_matched(14,12,20,2);
                    3008 .. 3071 : set_h_5_matched(15,12,20,2);
                    3072 .. 3135 : set_h_5_matched(16,12,20,2);
                    3136 .. 3199 : set_h_5_matched(17,12,20,2);
                    3200 .. 3263 : set_h_5_matched(18,12,20,2);
                    3264 .. 3327 : set_h_5_matched(19,12,20,2);
                    3328 .. 3391 : set_h_5_matched(20,12,20,2);
                    3392 .. 3455 : set_h_5_matched(21,12,20,2);
                    3456 .. 3519 : set_h_5_matched(22,12,20,2);
                    3520 .. 3583 : set_h_5_matched(23,12,20,2);
                    3584 .. 3647 : set_h_5_matched(24,12,20,2);
                    3648 .. 3711 : set_h_5_matched(25,12,20,2);
                    3712 .. 3775 : set_h_5_matched(26,12,20,2);
                    3776 .. 3839 : set_h_5_matched(27,12,20,2);
                    3840 .. 3903 : set_h_5_matched(28,12,20,2);
                    3904 .. 3967 : set_h_5_matched(29,12,20,2);
                    3968 .. 4031 : set_h_5_matched(30,12,20,2);
                    4032 .. 4095 : set_h_5_matched(31,12,20,2);
                    4096 .. 4159 : set_h_5_matched(0,18,20,7);
                    4160 .. 4223 : set_h_5_matched(1,18,20,7);
                    4224 .. 4287 : set_h_5_matched(2,18,20,7);
                    4288 .. 4351 : set_h_5_matched(3,18,20,7);
                    4352 .. 4415 : set_h_5_matched(4,18,20,7);
                    4416 .. 4479 : set_h_5_matched(5,18,20,7);
                    4480 .. 4543 : set_h_5_matched(6,18,20,7);
                    4544 .. 4607 : set_h_5_matched(7,18,20,7);
                    4608 .. 4671 : set_h_5_matched(8,18,20,7);
                    4672 .. 4735 : set_h_5_matched(9,18,20,7);
                    4736 .. 4799 : set_h_5_matched(10,18,20,7);
                    4800 .. 4863 : set_h_5_matched(11,18,20,7);
                    4864 .. 4927 : set_h_5_matched(12,18,20,7);
                    4928 .. 4991 : set_h_5_matched(13,18,20,7);
                    4992 .. 5055 : set_h_5_matched(14,18,20,7);
                    5056 .. 5119 : set_h_5_matched(15,18,20,7);
                    5120 .. 5183 : set_h_5_matched(16,18,20,7);
                    5184 .. 5247 : set_h_5_matched(17,18,20,7);
                    5248 .. 5311 : set_h_5_matched(18,18,20,7);
                    5312 .. 5375 : set_h_5_matched(19,18,20,7);
                    5376 .. 5439 : set_h_5_matched(20,18,20,7);
                    5440 .. 5503 : set_h_5_matched(21,18,20,7);
                    5504 .. 5567 : set_h_5_matched(22,18,20,7);
                    5568 .. 5631 : set_h_5_matched(23,18,20,7);
                    5632 .. 5695 : set_h_5_matched(24,18,20,7);
                    5696 .. 5759 : set_h_5_matched(25,18,20,7);
                    5760 .. 5823 : set_h_5_matched(26,18,20,7);
                    5824 .. 5887 : set_h_5_matched(27,18,20,7);
                    5888 .. 5951 : set_h_5_matched(28,18,20,7);
                    5952 .. 6015 : set_h_5_matched(29,18,20,7);
                    6016 .. 6079 : set_h_5_matched(30,18,20,7);
                    6080 .. 6143 : set_h_5_matched(31,18,20,7);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_6;
        action calc_hash_6_a(){
            ig_md.h_6 = hash_6.get({  16w43283,13w0,  hdr.ipv4.src_addr,hdr.tcp.src_port   });    
        }
        
        action set_h_6_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_6_activated=1;
            ig_md.h_6_cid=cid;
            ig_md.h_6_qid=qid;
            ig_md.h_6_ctotal=ctot;
            ig_md.h_6_keydefn=kdf;
        }
        action set_h_6_no_match(){
            ig_md.h_6_activated=0;
        }
        
        table tb_activate_coupons_h_6_ {
            key = {
                ig_md.h_6: range;
            }
            actions = {
                set_h_6_matched;
                set_h_6_no_match;
            }
            default_action = set_h_6_no_match();
            const entries = {
                    0 .. 63 : set_h_6_matched(0,11,20,4);
                    64 .. 127 : set_h_6_matched(1,11,20,4);
                    128 .. 191 : set_h_6_matched(2,11,20,4);
                    192 .. 255 : set_h_6_matched(3,11,20,4);
                    256 .. 319 : set_h_6_matched(4,11,20,4);
                    320 .. 383 : set_h_6_matched(5,11,20,4);
                    384 .. 447 : set_h_6_matched(6,11,20,4);
                    448 .. 511 : set_h_6_matched(7,11,20,4);
                    512 .. 575 : set_h_6_matched(8,11,20,4);
                    576 .. 639 : set_h_6_matched(9,11,20,4);
                    640 .. 703 : set_h_6_matched(10,11,20,4);
                    704 .. 767 : set_h_6_matched(11,11,20,4);
                    768 .. 831 : set_h_6_matched(12,11,20,4);
                    832 .. 895 : set_h_6_matched(13,11,20,4);
                    896 .. 959 : set_h_6_matched(14,11,20,4);
                    960 .. 1023 : set_h_6_matched(15,11,20,4);
                    1024 .. 1087 : set_h_6_matched(16,11,20,4);
                    1088 .. 1151 : set_h_6_matched(17,11,20,4);
                    1152 .. 1215 : set_h_6_matched(18,11,20,4);
                    1216 .. 1279 : set_h_6_matched(19,11,20,4);
                    1280 .. 1343 : set_h_6_matched(20,11,20,4);
                    1344 .. 1407 : set_h_6_matched(21,11,20,4);
                    1408 .. 1471 : set_h_6_matched(22,11,20,4);
                    1472 .. 1535 : set_h_6_matched(23,11,20,4);
                    1536 .. 1599 : set_h_6_matched(24,11,20,4);
                    1600 .. 1663 : set_h_6_matched(25,11,20,4);
                    1664 .. 1727 : set_h_6_matched(26,11,20,4);
                    1728 .. 1791 : set_h_6_matched(27,11,20,4);
                    1792 .. 1855 : set_h_6_matched(28,11,20,4);
                    1856 .. 1919 : set_h_6_matched(29,11,20,4);
                    1920 .. 1983 : set_h_6_matched(30,11,20,4);
                    1984 .. 2047 : set_h_6_matched(31,11,20,4);
                    2048 .. 2111 : set_h_6_matched(0,13,20,2);
                    2112 .. 2175 : set_h_6_matched(1,13,20,2);
                    2176 .. 2239 : set_h_6_matched(2,13,20,2);
                    2240 .. 2303 : set_h_6_matched(3,13,20,2);
                    2304 .. 2367 : set_h_6_matched(4,13,20,2);
                    2368 .. 2431 : set_h_6_matched(5,13,20,2);
                    2432 .. 2495 : set_h_6_matched(6,13,20,2);
                    2496 .. 2559 : set_h_6_matched(7,13,20,2);
                    2560 .. 2623 : set_h_6_matched(8,13,20,2);
                    2624 .. 2687 : set_h_6_matched(9,13,20,2);
                    2688 .. 2751 : set_h_6_matched(10,13,20,2);
                    2752 .. 2815 : set_h_6_matched(11,13,20,2);
                    2816 .. 2879 : set_h_6_matched(12,13,20,2);
                    2880 .. 2943 : set_h_6_matched(13,13,20,2);
                    2944 .. 3007 : set_h_6_matched(14,13,20,2);
                    3008 .. 3071 : set_h_6_matched(15,13,20,2);
                    3072 .. 3135 : set_h_6_matched(16,13,20,2);
                    3136 .. 3199 : set_h_6_matched(17,13,20,2);
                    3200 .. 3263 : set_h_6_matched(18,13,20,2);
                    3264 .. 3327 : set_h_6_matched(19,13,20,2);
                    3328 .. 3391 : set_h_6_matched(20,13,20,2);
                    3392 .. 3455 : set_h_6_matched(21,13,20,2);
                    3456 .. 3519 : set_h_6_matched(22,13,20,2);
                    3520 .. 3583 : set_h_6_matched(23,13,20,2);
                    3584 .. 3647 : set_h_6_matched(24,13,20,2);
                    3648 .. 3711 : set_h_6_matched(25,13,20,2);
                    3712 .. 3775 : set_h_6_matched(26,13,20,2);
                    3776 .. 3839 : set_h_6_matched(27,13,20,2);
                    3840 .. 3903 : set_h_6_matched(28,13,20,2);
                    3904 .. 3967 : set_h_6_matched(29,13,20,2);
                    3968 .. 4031 : set_h_6_matched(30,13,20,2);
                    4032 .. 4095 : set_h_6_matched(31,13,20,2);
                    4096 .. 4111 : set_h_6_matched(0,2,23,2);
                    4112 .. 4127 : set_h_6_matched(1,2,23,2);
                    4128 .. 4143 : set_h_6_matched(2,2,23,2);
                    4144 .. 4159 : set_h_6_matched(3,2,23,2);
                    4160 .. 4175 : set_h_6_matched(4,2,23,2);
                    4176 .. 4191 : set_h_6_matched(5,2,23,2);
                    4192 .. 4207 : set_h_6_matched(6,2,23,2);
                    4208 .. 4223 : set_h_6_matched(7,2,23,2);
                    4224 .. 4239 : set_h_6_matched(8,2,23,2);
                    4240 .. 4255 : set_h_6_matched(9,2,23,2);
                    4256 .. 4271 : set_h_6_matched(10,2,23,2);
                    4272 .. 4287 : set_h_6_matched(11,2,23,2);
                    4288 .. 4303 : set_h_6_matched(12,2,23,2);
                    4304 .. 4319 : set_h_6_matched(13,2,23,2);
                    4320 .. 4335 : set_h_6_matched(14,2,23,2);
                    4336 .. 4351 : set_h_6_matched(15,2,23,2);
                    4352 .. 4367 : set_h_6_matched(16,2,23,2);
                    4368 .. 4383 : set_h_6_matched(17,2,23,2);
                    4384 .. 4399 : set_h_6_matched(18,2,23,2);
                    4400 .. 4415 : set_h_6_matched(19,2,23,2);
                    4416 .. 4431 : set_h_6_matched(20,2,23,2);
                    4432 .. 4447 : set_h_6_matched(21,2,23,2);
                    4448 .. 4463 : set_h_6_matched(22,2,23,2);
                    4464 .. 4479 : set_h_6_matched(23,2,23,2);
                    4480 .. 4495 : set_h_6_matched(24,2,23,2);
                    4496 .. 4511 : set_h_6_matched(25,2,23,2);
                    4512 .. 4527 : set_h_6_matched(26,2,23,2);
                    4528 .. 4543 : set_h_6_matched(27,2,23,2);
                    4544 .. 4559 : set_h_6_matched(28,2,23,2);
                    4560 .. 4575 : set_h_6_matched(29,2,23,2);
                    4576 .. 4591 : set_h_6_matched(30,2,23,2);
                    4592 .. 4607 : set_h_6_matched(31,2,23,2);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_7;
        action calc_hash_7_a(){
            ig_md.h_7 = hash_7.get({  16w46000,2w0,  hdr.ipv4.src_addr,hdr.udp.src_port   });    
        }
        
        action set_h_7_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_7_activated=1;
            ig_md.h_7_cid=cid;
            ig_md.h_7_qid=qid;
            ig_md.h_7_ctotal=ctot;
            ig_md.h_7_keydefn=kdf;
        }
        action set_h_7_no_match(){
            ig_md.h_7_activated=0;
        }
        
        table tb_activate_coupons_h_7_ {
            key = {
                ig_md.h_7: range;
            }
            actions = {
                set_h_7_matched;
                set_h_7_no_match;
            }
            default_action = set_h_7_no_match();
            const entries = {
                    0 .. 63 : set_h_7_matched(0,17,20,4);
                    64 .. 127 : set_h_7_matched(1,17,20,4);
                    128 .. 191 : set_h_7_matched(2,17,20,4);
                    192 .. 255 : set_h_7_matched(3,17,20,4);
                    256 .. 319 : set_h_7_matched(4,17,20,4);
                    320 .. 383 : set_h_7_matched(5,17,20,4);
                    384 .. 447 : set_h_7_matched(6,17,20,4);
                    448 .. 511 : set_h_7_matched(7,17,20,4);
                    512 .. 575 : set_h_7_matched(8,17,20,4);
                    576 .. 639 : set_h_7_matched(9,17,20,4);
                    640 .. 703 : set_h_7_matched(10,17,20,4);
                    704 .. 767 : set_h_7_matched(11,17,20,4);
                    768 .. 831 : set_h_7_matched(12,17,20,4);
                    832 .. 895 : set_h_7_matched(13,17,20,4);
                    896 .. 959 : set_h_7_matched(14,17,20,4);
                    960 .. 1023 : set_h_7_matched(15,17,20,4);
                    1024 .. 1087 : set_h_7_matched(16,17,20,4);
                    1088 .. 1151 : set_h_7_matched(17,17,20,4);
                    1152 .. 1215 : set_h_7_matched(18,17,20,4);
                    1216 .. 1279 : set_h_7_matched(19,17,20,4);
                    1280 .. 1343 : set_h_7_matched(20,17,20,4);
                    1344 .. 1407 : set_h_7_matched(21,17,20,4);
                    1408 .. 1471 : set_h_7_matched(22,17,20,4);
                    1472 .. 1535 : set_h_7_matched(23,17,20,4);
                    1536 .. 1599 : set_h_7_matched(24,17,20,4);
                    1600 .. 1663 : set_h_7_matched(25,17,20,4);
                    1664 .. 1727 : set_h_7_matched(26,17,20,4);
                    1728 .. 1791 : set_h_7_matched(27,17,20,4);
                    1792 .. 1855 : set_h_7_matched(28,17,20,4);
                    1856 .. 1919 : set_h_7_matched(29,17,20,4);
                    1920 .. 1983 : set_h_7_matched(30,17,20,4);
                    1984 .. 2047 : set_h_7_matched(31,17,20,4);
                    2048 .. 2111 : set_h_7_matched(0,19,20,7);
                    2112 .. 2175 : set_h_7_matched(1,19,20,7);
                    2176 .. 2239 : set_h_7_matched(2,19,20,7);
                    2240 .. 2303 : set_h_7_matched(3,19,20,7);
                    2304 .. 2367 : set_h_7_matched(4,19,20,7);
                    2368 .. 2431 : set_h_7_matched(5,19,20,7);
                    2432 .. 2495 : set_h_7_matched(6,19,20,7);
                    2496 .. 2559 : set_h_7_matched(7,19,20,7);
                    2560 .. 2623 : set_h_7_matched(8,19,20,7);
                    2624 .. 2687 : set_h_7_matched(9,19,20,7);
                    2688 .. 2751 : set_h_7_matched(10,19,20,7);
                    2752 .. 2815 : set_h_7_matched(11,19,20,7);
                    2816 .. 2879 : set_h_7_matched(12,19,20,7);
                    2880 .. 2943 : set_h_7_matched(13,19,20,7);
                    2944 .. 3007 : set_h_7_matched(14,19,20,7);
                    3008 .. 3071 : set_h_7_matched(15,19,20,7);
                    3072 .. 3135 : set_h_7_matched(16,19,20,7);
                    3136 .. 3199 : set_h_7_matched(17,19,20,7);
                    3200 .. 3263 : set_h_7_matched(18,19,20,7);
                    3264 .. 3327 : set_h_7_matched(19,19,20,7);
                    3328 .. 3391 : set_h_7_matched(20,19,20,7);
                    3392 .. 3455 : set_h_7_matched(21,19,20,7);
                    3456 .. 3519 : set_h_7_matched(22,19,20,7);
                    3520 .. 3583 : set_h_7_matched(23,19,20,7);
                    3584 .. 3647 : set_h_7_matched(24,19,20,7);
                    3648 .. 3711 : set_h_7_matched(25,19,20,7);
                    3712 .. 3775 : set_h_7_matched(26,19,20,7);
                    3776 .. 3839 : set_h_7_matched(27,19,20,7);
                    3840 .. 3903 : set_h_7_matched(28,19,20,7);
                    3904 .. 3967 : set_h_7_matched(29,19,20,7);
                    3968 .. 4031 : set_h_7_matched(30,19,20,7);
                    4032 .. 4095 : set_h_7_matched(31,19,20,7);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_8;
        action calc_hash_8_a(){
            ig_md.h_8 = hash_8.get({  16w51526,7w0,  hdr.tcp.dst_port   });    
        }
        
        action set_h_8_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_8_activated=1;
            ig_md.h_8_cid=cid;
            ig_md.h_8_qid=qid;
            ig_md.h_8_ctotal=ctot;
            ig_md.h_8_keydefn=kdf;
        }
        action set_h_8_no_match(){
            ig_md.h_8_activated=0;
        }
        
        table tb_activate_coupons_h_8_ {
            key = {
                ig_md.h_8: range;
            }
            actions = {
                set_h_8_matched;
                set_h_8_no_match;
            }
            default_action = set_h_8_no_match();
            const entries = {
                    0 .. 255 : set_h_8_matched(0,3,3,3);
                    256 .. 511 : set_h_8_matched(1,3,3,3);
                    512 .. 767 : set_h_8_matched(2,3,3,3);
                    768 .. 1023 : set_h_8_matched(3,3,3,3);
                    1024 .. 1279 : set_h_8_matched(4,3,3,3);
                    1280 .. 1535 : set_h_8_matched(5,3,3,3);
                    1536 .. 1791 : set_h_8_matched(6,3,3,3);
                    1792 .. 2047 : set_h_8_matched(7,3,3,3);
                    2048 .. 2303 : set_h_8_matched(8,3,3,3);
                    2304 .. 2559 : set_h_8_matched(0,5,3,4);
                    2560 .. 2815 : set_h_8_matched(1,5,3,4);
                    2816 .. 3071 : set_h_8_matched(2,5,3,4);
                    3072 .. 3327 : set_h_8_matched(3,5,3,4);
                    3328 .. 3583 : set_h_8_matched(4,5,3,4);
                    3584 .. 3839 : set_h_8_matched(5,5,3,4);
                    3840 .. 4095 : set_h_8_matched(6,5,3,4);
                    4096 .. 4351 : set_h_8_matched(7,5,3,4);
                    4352 .. 4607 : set_h_8_matched(8,5,3,4);
                    4608 .. 4735 : set_h_8_matched(0,20,12,8);
                    4736 .. 4863 : set_h_8_matched(1,20,12,8);
                    4864 .. 4991 : set_h_8_matched(2,20,12,8);
                    4992 .. 5119 : set_h_8_matched(3,20,12,8);
                    5120 .. 5247 : set_h_8_matched(4,20,12,8);
                    5248 .. 5375 : set_h_8_matched(5,20,12,8);
                    5376 .. 5503 : set_h_8_matched(6,20,12,8);
                    5504 .. 5631 : set_h_8_matched(7,20,12,8);
                    5632 .. 5759 : set_h_8_matched(8,20,12,8);
                    5760 .. 5887 : set_h_8_matched(9,20,12,8);
                    5888 .. 6015 : set_h_8_matched(10,20,12,8);
                    6016 .. 6143 : set_h_8_matched(11,20,12,8);
                    6144 .. 6271 : set_h_8_matched(12,20,12,8);
                    6272 .. 6399 : set_h_8_matched(13,20,12,8);
                    6400 .. 6527 : set_h_8_matched(14,20,12,8);
                    6528 .. 6655 : set_h_8_matched(15,20,12,8);
                    6656 .. 6783 : set_h_8_matched(16,20,12,8);
                    6784 .. 6911 : set_h_8_matched(17,20,12,8);
                    6912 .. 7039 : set_h_8_matched(18,20,12,8);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_9;
        action calc_hash_9_a(){
            ig_md.h_9 = hash_9.get({  16w51600,12w0,  hdr.tcp.src_port   });    
        }
        
        action set_h_9_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_9_activated=1;
            ig_md.h_9_cid=cid;
            ig_md.h_9_qid=qid;
            ig_md.h_9_ctotal=ctot;
            ig_md.h_9_keydefn=kdf;
        }
        action set_h_9_no_match(){
            ig_md.h_9_activated=0;
        }
        
        table tb_activate_coupons_h_9_ {
            key = {
                ig_md.h_9: range;
            }
            actions = {
                set_h_9_matched;
                set_h_9_no_match;
            }
            default_action = set_h_9_no_match();
            const entries = {
                    0 .. 255 : set_h_9_matched(0,22,3,10);
                    256 .. 511 : set_h_9_matched(1,22,3,10);
                    512 .. 767 : set_h_9_matched(2,22,3,10);
                    768 .. 1023 : set_h_9_matched(3,22,3,10);
                    1024 .. 1279 : set_h_9_matched(4,22,3,10);
                    1280 .. 1535 : set_h_9_matched(5,22,3,10);
                    1536 .. 1791 : set_h_9_matched(6,22,3,10);
                    1792 .. 2047 : set_h_9_matched(7,22,3,10);
                    2048 .. 2303 : set_h_9_matched(8,22,3,10);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_10;
        action calc_hash_10_a(){
            ig_md.h_10 = hash_10.get({  16w21727,11w0,  hdr.udp.dst_port   });    
        }
        
        action set_h_10_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_10_activated=1;
            ig_md.h_10_cid=cid;
            ig_md.h_10_qid=qid;
            ig_md.h_10_ctotal=ctot;
            ig_md.h_10_keydefn=kdf;
        }
        action set_h_10_no_match(){
            ig_md.h_10_activated=0;
        }
        
        table tb_activate_coupons_h_10_ {
            key = {
                ig_md.h_10: range;
            }
            actions = {
                set_h_10_matched;
                set_h_10_no_match;
            }
            default_action = set_h_10_no_match();
            const entries = {
                    0 .. 255 : set_h_10_matched(0,4,3,3);
                    256 .. 511 : set_h_10_matched(1,4,3,3);
                    512 .. 767 : set_h_10_matched(2,4,3,3);
                    768 .. 1023 : set_h_10_matched(3,4,3,3);
                    1024 .. 1279 : set_h_10_matched(4,4,3,3);
                    1280 .. 1535 : set_h_10_matched(5,4,3,3);
                    1536 .. 1791 : set_h_10_matched(6,4,3,3);
                    1792 .. 2047 : set_h_10_matched(7,4,3,3);
                    2048 .. 2303 : set_h_10_matched(8,4,3,3);
                    2304 .. 2431 : set_h_10_matched(0,21,12,9);
                    2432 .. 2559 : set_h_10_matched(1,21,12,9);
                    2560 .. 2687 : set_h_10_matched(2,21,12,9);
                    2688 .. 2815 : set_h_10_matched(3,21,12,9);
                    2816 .. 2943 : set_h_10_matched(4,21,12,9);
                    2944 .. 3071 : set_h_10_matched(5,21,12,9);
                    3072 .. 3199 : set_h_10_matched(6,21,12,9);
                    3200 .. 3327 : set_h_10_matched(7,21,12,9);
                    3328 .. 3455 : set_h_10_matched(8,21,12,9);
                    3456 .. 3583 : set_h_10_matched(9,21,12,9);
                    3584 .. 3711 : set_h_10_matched(10,21,12,9);
                    3712 .. 3839 : set_h_10_matched(11,21,12,9);
                    3840 .. 3967 : set_h_10_matched(12,21,12,9);
                    3968 .. 4095 : set_h_10_matched(13,21,12,9);
                    4096 .. 4223 : set_h_10_matched(14,21,12,9);
                    4224 .. 4351 : set_h_10_matched(15,21,12,9);
                    4352 .. 4479 : set_h_10_matched(16,21,12,9);
                    4480 .. 4607 : set_h_10_matched(17,21,12,9);
                    4608 .. 4735 : set_h_10_matched(18,21,12,9);
            }
        }

        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_11;
        action calc_hash_11_a(){
            ig_md.h_11 = hash_11.get({  16w17320,10w0,  hdr.udp.src_port   });    
        }
        
        action set_h_11_matched(bit<8> cid,bit<8> qid,bit<8> ctot,bit<4> kdf){
            ig_md.h_11_activated=1;
            ig_md.h_11_cid=cid;
            ig_md.h_11_qid=qid;
            ig_md.h_11_ctotal=ctot;
            ig_md.h_11_keydefn=kdf;
        }
        action set_h_11_no_match(){
            ig_md.h_11_activated=0;
        }
        
        table tb_activate_coupons_h_11_ {
            key = {
                ig_md.h_11: range;
            }
            actions = {
                set_h_11_matched;
                set_h_11_no_match;
            }
            default_action = set_h_11_no_match();
            const entries = {
                    0 .. 255 : set_h_11_matched(0,23,3,11);
                    256 .. 511 : set_h_11_matched(1,23,3,11);
                    512 .. 767 : set_h_11_matched(2,23,3,11);
                    768 .. 1023 : set_h_11_matched(3,23,3,11);
                    1024 .. 1279 : set_h_11_matched(4,23,3,11);
                    1280 .. 1535 : set_h_11_matched(5,23,3,11);
                    1536 .. 1791 : set_h_11_matched(6,23,3,11);
                    1792 .. 2047 : set_h_11_matched(7,23,3,11);
                    2048 .. 2303 : set_h_11_matched(8,23,3,11);
            }
        }


		// tiebreaking entropy
        action prepare_timestamp(){
            ig_md.current_timestamp=(bit<32>)ig_intr_md.ingress_mac_tstamp;
        }
        Random< bit<1> >() rng;
        action prepare_random_1_bit(){
            ig_md.random_1_bit = rng.get();
        }

        //after having the hash, let's do tiebreaking
        action actb_select_h_1_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_1_cid;
            ig_md.h_s_qid=ig_md.h_1_qid;
            ig_md.h_s_ctotal=ig_md.h_1_ctotal;
            ig_md.h_s_keydefn=ig_md.h_1_keydefn;
        }
        action actb_select_h_2_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_2_cid;
            ig_md.h_s_qid=ig_md.h_2_qid;
            ig_md.h_s_ctotal=ig_md.h_2_ctotal;
            ig_md.h_s_keydefn=ig_md.h_2_keydefn;
        }
        action actb_select_h_3_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_3_cid;
            ig_md.h_s_qid=ig_md.h_3_qid;
            ig_md.h_s_ctotal=ig_md.h_3_ctotal;
            ig_md.h_s_keydefn=ig_md.h_3_keydefn;
        }
        action actb_select_h_4_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_4_cid;
            ig_md.h_s_qid=ig_md.h_4_qid;
            ig_md.h_s_ctotal=ig_md.h_4_ctotal;
            ig_md.h_s_keydefn=ig_md.h_4_keydefn;
        }
        action actb_select_h_5_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_5_cid;
            ig_md.h_s_qid=ig_md.h_5_qid;
            ig_md.h_s_ctotal=ig_md.h_5_ctotal;
            ig_md.h_s_keydefn=ig_md.h_5_keydefn;
        }
        action actb_select_h_6_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_6_cid;
            ig_md.h_s_qid=ig_md.h_6_qid;
            ig_md.h_s_ctotal=ig_md.h_6_ctotal;
            ig_md.h_s_keydefn=ig_md.h_6_keydefn;
        }
        action actb_select_h_7_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_7_cid;
            ig_md.h_s_qid=ig_md.h_7_qid;
            ig_md.h_s_ctotal=ig_md.h_7_ctotal;
            ig_md.h_s_keydefn=ig_md.h_7_keydefn;
        }
        action actb_select_h_8_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_8_cid;
            ig_md.h_s_qid=ig_md.h_8_qid;
            ig_md.h_s_ctotal=ig_md.h_8_ctotal;
            ig_md.h_s_keydefn=ig_md.h_8_keydefn;
        }
        action actb_select_h_9_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_9_cid;
            ig_md.h_s_qid=ig_md.h_9_qid;
            ig_md.h_s_ctotal=ig_md.h_9_ctotal;
            ig_md.h_s_keydefn=ig_md.h_9_keydefn;
        }
        action actb_select_h_10_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_10_cid;
            ig_md.h_s_qid=ig_md.h_10_qid;
            ig_md.h_s_ctotal=ig_md.h_10_ctotal;
            ig_md.h_s_keydefn=ig_md.h_10_keydefn;
        }
        action actb_select_h_11_(){
            ig_md.h_s_activated=1;
            ig_md.h_s_cid=ig_md.h_11_cid;
            ig_md.h_s_qid=ig_md.h_11_qid;
            ig_md.h_s_ctotal=ig_md.h_11_ctotal;
            ig_md.h_s_keydefn=ig_md.h_11_keydefn;
        }

        table tb_activated_coupon_tiebreaking {
            key = {
                ig_md.h_1_activated: ternary;
                ig_md.h_2_activated: ternary;
                ig_md.h_3_activated: ternary;
                ig_md.h_4_activated: ternary;
                ig_md.h_5_activated: ternary;
                ig_md.h_6_activated: ternary;
                ig_md.h_7_activated: ternary;
                ig_md.h_8_activated: ternary;
                ig_md.h_9_activated: ternary;
                ig_md.h_10_activated: ternary;
                ig_md.h_11_activated: ternary;
                ig_md.random_1_bit: ternary; 
            }
            actions = {
                actb_select_h_1_;
                actb_select_h_2_;
                actb_select_h_3_;
                actb_select_h_4_;
                actb_select_h_5_;
                actb_select_h_6_;
                actb_select_h_7_;
                actb_select_h_8_;
                actb_select_h_9_;
                actb_select_h_10_;
                actb_select_h_11_;
                nop;
            }
            default_action = nop();
            const entries = {
            // Part 0: no one is activated
                // only one rule
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : nop();
                
            // Part 1: only one activated
                // rule for only hash 1 is activated
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_1_();
                // rule for only hash 2 is activated
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_2_();
                // rule for only hash 3 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_3_();
                // rule for only hash 4 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_4_();
                // rule for only hash 5 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_5_();
                // rule for only hash 6 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_6_();
                // rule for only hash 7 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_7_();
                // rule for only hash 8 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_8_();
                // rule for only hash 9 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_9_();
                // rule for only hash 10 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_10_();
                // rule for only hash 11 is activated
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w0 ) : actb_select_h_11_();
            
            // Part 2: only two activated
                // rules for 1 and 2 
                // coin toss gives 1 
                ( 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 2 
                ( 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_2_();
                // rules for 1 and 3 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 3 
                ( 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_3_();
                // rules for 1 and 4 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 4 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_4_();
                // rules for 1 and 5 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 5 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_5_();
                // rules for 1 and 6 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 6 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_6_();
                // rules for 1 and 7 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 7 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_7_();
                // rules for 1 and 8 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 8 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_8_();
                // rules for 1 and 9 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 9 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 1 and 10 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 10 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 1 and 11 
                // coin toss gives 1 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_1_();
                // coin toss gives 11 
                ( 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 2 and 3 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 3 
                ( 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_3_();
                // rules for 2 and 4 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 4 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_4_();
                // rules for 2 and 5 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 5 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_5_();
                // rules for 2 and 6 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 6 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_6_();
                // rules for 2 and 7 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 7 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_7_();
                // rules for 2 and 8 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 8 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_8_();
                // rules for 2 and 9 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 9 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 2 and 10 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 2 and 11 
                // coin toss gives 2 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_2_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 3 and 4 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_4_();
                // rules for 3 and 5 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_5_();
                // rules for 3 and 6 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_6_();
                // rules for 3 and 7 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_7_();
                // rules for 3 and 8 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_8_();
                // rules for 3 and 9 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 3 and 10 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 3 and 11 
                // coin toss gives 3 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_3_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 4 and 5 
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_4_();
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_5_();
                // rules for 4 and 6 
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_4_();
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_6_();
                // rules for 4 and 7 
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_4_();
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_7_();
                // rules for 4 and 8 
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_4_();
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_8_();
                // rules for 4 and 9 
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_4_();
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 4 and 10 
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_4_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 4 and 11 
                // coin toss gives 4 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_4_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 5 and 6 
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_5_();
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_6_();
                // rules for 5 and 7 
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_5_();
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_7_();
                // rules for 5 and 8 
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_5_();
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_8_();
                // rules for 5 and 9 
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_5_();
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 5 and 10 
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_5_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 5 and 11 
                // coin toss gives 5 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_5_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 6 and 7 
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_6_();
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_7_();
                // rules for 6 and 8 
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_6_();
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_8_();
                // rules for 6 and 9 
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_6_();
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 6 and 10 
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_6_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 6 and 11 
                // coin toss gives 6 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_6_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 7 and 8 
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_7_();
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_8_();
                // rules for 7 and 9 
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_7_();
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 7 and 10 
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_7_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 7 and 11 
                // coin toss gives 7 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_7_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 8 and 9 
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_8_();
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_9_();
                // rules for 8 and 10 
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_8_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 8 and 11 
                // coin toss gives 8 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_8_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 9 and 10 
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_9_();
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_10_();
                // rules for 9 and 11 
                // coin toss gives 9 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_9_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
                // rules for 10 and 11 
                // coin toss gives 10 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1,  0 &&& 1w1 ) : actb_select_h_10_();
                // coin toss gives 11 
                ( 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 0 &&& 1w1, 1 &&& 1w1, 1 &&& 1w1,  1 &&& 1w1 ) : actb_select_h_11_();
            }
        }


        // Prepare onehot variable for one coupon
        action write_onehot(bit<32> o){
            ig_md.coupon_onehot = o;
        }
        table tb_set_onehot {
            key = {
                ig_md.h_s_cid: exact;
            }
            size = 32;
            actions = {
                write_onehot;
            }
            default_action = write_onehot(0);
            const entries = {
                  0 : write_onehot(32w0b1);
                  1 : write_onehot(32w0b10);
                  2 : write_onehot(32w0b100);
                  3 : write_onehot(32w0b1000);
                  4 : write_onehot(32w0b10000);
                  5 : write_onehot(32w0b100000);
                  6 : write_onehot(32w0b1000000);
                  7 : write_onehot(32w0b10000000);
                  8 : write_onehot(32w0b100000000);
                  9 : write_onehot(32w0b1000000000);
                  10 : write_onehot(32w0b10000000000);
                  11 : write_onehot(32w0b100000000000);
                  12 : write_onehot(32w0b1000000000000);
                  13 : write_onehot(32w0b10000000000000);
                  14 : write_onehot(32w0b100000000000000);
                  15 : write_onehot(32w0b1000000000000000);
                  16 : write_onehot(32w0b10000000000000000);
                  17 : write_onehot(32w0b100000000000000000);
                  18 : write_onehot(32w0b1000000000000000000);
                  19 : write_onehot(32w0b10000000000000000000);
                  20 : write_onehot(32w0b100000000000000000000);
                  21 : write_onehot(32w0b1000000000000000000000);
                  22 : write_onehot(32w0b10000000000000000000000);
                  23 : write_onehot(32w0b100000000000000000000000);
                  24 : write_onehot(32w0b1000000000000000000000000);
                  25 : write_onehot(32w0b10000000000000000000000000);
                  26 : write_onehot(32w0b100000000000000000000000000);
                  27 : write_onehot(32w0b1000000000000000000000000000);
                  28 : write_onehot(32w0b10000000000000000000000000000);
                  29 : write_onehot(32w0b100000000000000000000000000000);
                  30 : write_onehot(32w0b1000000000000000000000000000000);
                  31 : write_onehot(32w0b10000000000000000000000000000000);
            }
        }

        // ======== Section 2: having one coupon, find flow key for this query

        Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_1;
        Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_2;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_1;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_2;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_3;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy16_4;


        // 128-bit key, split into 4 parts.
        //6 choices: srcip,dstip,tcp sport,dport, udp sport,dport
        action ek_c1_select(){
            ig_md.key_p1=copy32_1.get({hdr.ipv4.src_addr});
        }
        action ek_c1_erase(){
            ig_md.key_p1=0;
        }
        table tb_extract_key_choice_1_ {
            key = {
                ig_md.h_s_keydefn: exact;
            }
            size = 16;
            actions = {
                ek_c1_select;
                ek_c1_erase;
            }
            const entries = {
                  1 : ek_c1_select();
                  3 : ek_c1_select();
                  5 : ek_c1_select();
                  6 : ek_c1_select();
                  8 : ek_c1_select();
                  9 : ek_c1_select();
                  10 : ek_c1_select();
                  11 : ek_c1_select();
                  12 : ek_c1_select();
            }
            default_action = ek_c1_erase;
        }

        action ek_c2_select(){
            ig_md.key_p2=copy32_2.get({hdr.ipv4.dst_addr});
        }
        action ek_c2_erase(){
            ig_md.key_p2=0;
        }
        table tb_extract_key_choice_2_ {
            key = {
                ig_md.h_s_keydefn: exact;
            }
            size = 16;
            actions = {
                ek_c2_select;
                ek_c2_erase;
            }
            const entries = {
                  2 : ek_c2_select();
                  3 : ek_c2_select();
                  4 : ek_c2_select();
                  7 : ek_c2_select();
                  8 : ek_c2_select();
                  9 : ek_c2_select();
                  10 : ek_c2_select();
                  11 : ek_c2_select();
                  12 : ek_c2_select();
            }
            default_action = ek_c2_erase;
        }

        action ek_c3_select_tcp(){
            ig_md.key_p3=copy16_1.get({hdr.tcp.src_port});
        }
        action ek_c3_select_udp(){
            ig_md.key_p3=copy16_2.get({hdr.udp.src_port});
        }
        action ek_c3_erase(){
            ig_md.key_p3=0;
        }
        table tb_extract_key_choice_3_ {
            key = {
                ig_md.h_s_keydefn: exact;
            }
            size = 16;
            actions = {
                ek_c3_select_tcp;
                ek_c3_select_udp;
                ek_c3_erase;
            }
            const entries = {
                  8 : ek_c3_select_tcp();
                  9 : ek_c3_select_udp();
                  12 : ek_c3_select_tcp();
            }
            default_action = ek_c3_erase;
        }

        action ek_c4_select_tcp(){
            ig_md.key_p4=copy16_3.get({hdr.tcp.dst_port});
        }
        action ek_c4_select_udp(){
            ig_md.key_p4=copy16_4.get({hdr.udp.dst_port});
        }
        action ek_c4_erase(){
            ig_md.key_p4=0;
        }
        table tb_extract_key_choice_4_ {
            key = {
                ig_md.h_s_keydefn: exact;
            }
            size = 16;
            actions = {
                ek_c4_select_tcp;
                ek_c4_select_udp;
                ek_c4_erase;
            }
            const entries = {
                  2 : ek_c4_select_tcp();
                  5 : ek_c4_select_tcp();
                  6 : ek_c4_select_udp();
                  7 : ek_c4_select_udp();
                  10 : ek_c4_select_tcp();
                  11 : ek_c4_select_udp();
                  12 : ek_c4_select_tcp();
            }
            default_action = ek_c4_erase;
        }


        Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_key_sig;
        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_key_loc;
            //based on full flowID, select memory location and a 32-bit sig
        action extract_key_sig (){
            ig_md.key_sig=hash_key_sig.get({ ig_md.h_s_qid,  ig_md.key_p1,ig_md.key_p2,ig_md.key_p3,ig_md.key_p4});
        }
        action extract_key_loc (){
            ig_md.key_loc=hash_key_loc.get({ ig_md.h_s_qid,  ig_md.key_p1,ig_md.key_p2,ig_md.key_p3,ig_md.key_p4});
        }

        // ======== Section 3: actually try to collect this coupon 
        // pseudocode
        // 1. if timestamp[idx]< current_timestamp - window:
        //      flag=clear, timestamp[idx] = current_timestamp
        //    else:
        //      flag=continue (do nothing)
        // 2. clear: 
        //      curr_key[idx]=key_sig, flag2=clear
        // 2. continue:
        //    if curr_key[idx]==key_sig:
        //      flag2=incr
        //    else:
        //       stop
        // 3. clear:
        //       coupons[idx]=onehot, ctr[idx]=1, result=false
        // 3. incr:
        //       coupons[idx] ^= onehot, if coupons[idx]&onehot == 0: ctr[idx]+=1, result=(ctr[idx]>=CTOT)
        //      

        // 3.1 decay check

        Register<bit<32>,_ >(65536) reg_decay_timestamp;
        RegisterAction<bit<32>, _, bit<1>>(reg_decay_timestamp) check_decay_timestamp = {
            void apply(inout bit<32> value, out bit<1> read_value){
                bit<32> in_value;
                in_value = value;
                if(in_value + DECAY_TIME_WINDOW < ig_md.current_timestamp)//expired
                {
                    value = ig_md.current_timestamp;
                    read_value = 1;
                }else{
                    value = in_value;
                    read_value = 0;
                }
            }
        };
        action exec_check_decay_timestamp(){
            ig_md.cf_decay_has_expired = check_decay_timestamp.execute(ig_md.key_loc);
        }



        // 3.2 what is the current key+qid sig?
        //when flush, write into these
        Register<bit<32>,_ >(65536) reg_current_keysig;
        RegisterAction<bit<32>, _, bit<1>>(reg_current_keysig) write_keysig = {
            void apply(inout bit<32> value, out bit<1> read_value){
                value=ig_md.key_sig;
                read_value=1;
            }
        };
        action exec_write_keysig(){
            write_keysig.execute(ig_md.key_loc);
            ig_md.cf_key_matched=1;
        }

        RegisterAction<bit<32>, _, bit<1>>(reg_current_keysig) check_keysig = {
            void apply(inout bit<32> value, out bit<1> read_value){
                if(value == ig_md.key_sig){
                    read_value=1;
                }else{
                    read_value=0;
                }
            }
        };
        action exec_check_keysig(){
            ig_md.cf_key_matched=check_keysig.execute(ig_md.key_loc);
        }


        // 2.3 actually write coupon!

        Register<paired_32bit, _ >(65536) reg_coupons;
        //logic: flush simply sets 1 coupon. merge will output the old 32-bit (later count)
        RegisterAction<paired_32bit, _, bit<32>>(reg_coupons) regcoupon_flush = {
             void apply(inout paired_32bit value, out bit<32> rv) {         
                rv = 0;                                               
                paired_32bit in_value;                                     
                in_value = value;                                     
                value.lo =  ig_md.coupon_onehot;
                value.hi = 0;
                rv = 0;
            }                             
        };
        action exec_regcoupon_flush(){
            regcoupon_flush.execute(ig_md.key_loc);
            ig_md.coupon_merge_check = 0;
        }
        RegisterAction<paired_32bit, _, bit<32>>(reg_coupons) regcoupon_merge = {
             void apply(inout paired_32bit value, out bit<32> rv) {         
                rv = 0;                                               
                paired_32bit in_value;                                     
                in_value = value;                                     
                value.lo =  in_value.lo | ig_md.coupon_onehot;
                value.hi = in_value.lo & ig_md.coupon_onehot;
                rv = value.hi;
            }                             
        };
        action exec_regcoupon_merge(){
            ig_md.coupon_merge_check = regcoupon_merge.execute(ig_md.key_loc);
        }

        Register<bit<32>,_ >(65536) reg_counter_activated;
        RegisterAction<bit<32>, _, bit<32>>(reg_counter_activated) counter_incr = {
            void apply(inout bit<32> value, out bit<32> read_value){
                bit<32> in_value=value;
                value=in_value+1;
                read_value=value;
            }
        };
        action exec_counter_incr(){
            ig_md.coupon_total_activated = (bit<8>) counter_incr.execute(ig_md.key_loc);
        }

        RegisterAction<bit<32>, _, bit<32>>(reg_counter_activated) counter_set_to_one = {
            void apply(inout bit<32> value, out bit<32> read_value){
                value=1;
                read_value=value;
            }
        };
        action exec_counter_set_to_one(){
            ig_md.coupon_total_activated = (bit<8>) counter_set_to_one.execute(ig_md.key_loc);
        }



        apply {

            calc_hash_1_a();
            calc_hash_2_a();
            calc_hash_3_a();
            calc_hash_4_a();
            calc_hash_5_a();
            calc_hash_6_a();
            calc_hash_7_a();
            calc_hash_8_a();
            calc_hash_9_a();
            calc_hash_10_a();
            calc_hash_11_a();

            prepare_timestamp();
            prepare_random_1_bit();


            tb_activate_coupons_h_1_.apply();
            tb_activate_coupons_h_2_.apply();
            tb_activate_coupons_h_3_.apply();
            tb_activate_coupons_h_4_.apply();
            tb_activate_coupons_h_5_.apply();
            tb_activate_coupons_h_6_.apply();
            tb_activate_coupons_h_7_.apply();
            tb_activate_coupons_h_8_.apply();
            tb_activate_coupons_h_9_.apply();
            tb_activate_coupons_h_10_.apply();
            tb_activate_coupons_h_11_.apply();


            tb_activated_coupon_tiebreaking.apply();

            // no coupon? stop processing
            if(ig_md.h_s_activated==0){
                drop_and_exit();
            }
            // now we do have coupon, collect it...

            tb_set_onehot.apply();

            tb_extract_key_choice_1_.apply();
            tb_extract_key_choice_2_.apply();
            tb_extract_key_choice_3_.apply();
            tb_extract_key_choice_4_.apply();

            extract_key_sig();
            extract_key_loc();

            exec_check_decay_timestamp();
            if(ig_md.cf_decay_has_expired==1){
                exec_write_keysig();
            }else{
                exec_check_keysig();
            }

            if(ig_md.cf_decay_has_expired==1){
                exec_regcoupon_flush();
            }else{
                if(ig_md.cf_key_matched==1){
                    exec_regcoupon_merge();
                }
            }

            bool cf_new_coupon_collected = (ig_md.coupon_merge_check==0);
            if(ig_md.cf_decay_has_expired==1){
                exec_counter_set_to_one();
            }else{
                if(ig_md.cf_key_matched==1 && cf_new_coupon_collected){
                    exec_counter_incr();
                }
            }

            //finally, check coupon count: do we have enough coupons to send an alert?
            if(ig_md.coupon_total_activated == ig_md.h_s_ctotal){
                // Report a query key: add a flag, send to control plane / mirror session, etc
                
                // For now, we mark the ethernet headers for alert. 
                // Only reporting query ID is enough (query key can be reconstructed from header).
                hdr.ethernet.dst_addr[7:0] = ig_md.h_s_qid;
                hdr.ethernet.src_addr[7:0] = 233;
                //hdr.ethernet.src_addr[47:8] = 0;
                //hdr.ethernet.dst_addr[47:8] = 0;
                
                //For debugging with mirrored traffic, alert packets are routed back to sender
                reflect();
            } else {
                drop_and_exit();
            }
           
        }
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {
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
