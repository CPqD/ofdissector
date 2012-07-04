/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */
// Copyright (c) 2012 Barnstormer Softworks Ltd.

#define OPENFLOW_INTERNAL

#include <iostream>

#include <of11/openflow-110.hpp>
#include <openflow-common.hpp>

#include <string.h>

#if defined(__cplusplus)
extern "C" {
#endif

#include <epan/dissectors/packet-tcp.h>
#include <epan/value_string.h>

#if defined(__cplusplus)
}
#endif

class ZeroLenInstruction { };
class ZeroLenAction { };
class ZeroLenBucket { };

#define PROTO_TAG_OPENFLOW_VER "OFP 1.1"

#define WC_FM_INPORT  0x0001
#define WC_FM_VLAN    0x0002
#define WC_FM_VLANPCP 0x0004
#define WC_FM_ETHTYPE 0x0008
#define WC_FM_IPDSCP  0x0010
#define WC_FM_IPPROTO 0x0020
#define WC_FM_IPSRCP  0x0040
#define WC_FM_IPDSTP  0x0080
#define WC_FM_MPLSLBL 0x0100
#define WC_FM_MPLSTC  0x0200
#define WC_FM_RES     0xFFFFFC00

#define CAP_FLOWSTATS   0x0001
#define CAP_TABLESTATS  0x0002
#define CAP_PORTSTATS   0x0004
#define CAP_GROUPSTATS  0x0008
#define CAP_IPREASM     0x0010
#define CAP_QUEUESTATS  0x0020
#define CAP_ARPMATCHIP  0x0040
#define CAP_RESERVED    0xFFFFFF80

#define PPC_DOWN        0x0001
#define PPC_NORECV      0x0004
#define PPC_NOFWD       0x0020
#define PPC_NOPACKETIN  0x0040
#define PPC_RESERVED    0xFFFFFF9A

#define PPS_LINKDOWN    0x0001
#define PPS_BLOCKED     0x0002
#define PPS_LIVE        0x0004
#define PPS_RESERVED    0xFFFFFFF8

#define PPF_10MBHD      0x0001
#define PPF_10MBFD      0x0002
#define PPF_100MBHD     0x0004
#define PPF_100MBFD     0x0008
#define PPF_1GBHD       0x0010
#define PPF_1GBFD       0x0020
#define PPF_10GBFD      0x0040
#define PPF_40GBFD      0x0080
#define PPF_100GBFD     0x0100
#define PPF_1TBFD       0x0200
#define PPF_LUDICROUS   0x0400
#define PPF_COPPER      0x0800
#define PPF_FIBER       0x1000
#define PPF_AUTONEG     0x2000
#define PPF_PAUSE       0x4000
#define PPF_PAUSEASYM   0x8000
#define PPF_RESERVED    0xFFFF0000

#define SCF_DROP        0x0001
#define SCF_REASM       0x0002
#define SCF_INVALIDTTL  0x0004
#define SCF_RESERVED    0xFFF4

#define TMC_MISS_CONTINUE 0x0001
#define TMC_MISS_DROP     0x0002
#define TMC_RESERVED      0xfffffffc

namespace openflow_110
  {
  DissectorContext * DissectorContext::mSingle = NULL;
  DissectorContext * Context;

  DissectorContext::DissectorContext (int proto_openflow)
    : mProtoOpenflow(proto_openflow), mFM(proto_openflow, "of11")
    {
    Context = this;

    this->setupTypes();
    this->setupStatsTypes();
    this->setupErrorTypes();
    this->setupPortReasonTypes();
    this->setupGroupModTypes();

    this->setupFields();

    this->mFM.doRegister();
    }

  void
  DissectorContext::setupFields (void)
    {
    this->mFM.createField("data", "Openflow Protocol", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("pad", "Pad", FT_BYTES, BASE_NONE, NULL, 0x0);

    // Header
    this->mFM.createField("header", "Header", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("ver", "Version", FT_UINT8, BASE_HEX, NULL, 0x0);
    this->mFM.createField("type", "Type", FT_UINT8, BASE_DEC, (void*) VALS(this->mTypeArray->data), 0x0);
    this->mFM.createField("len", "Length", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("xid", "Transaction ID", FT_UINT32, BASE_DEC, NULL, 0x0);

    // Echo Request/Reply
    this->mFM.createField("echo", "Echo Data", FT_STRING, BASE_NONE, NULL, 0x0);

    // Error
    this->mFM.createField("err", "Error", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("err.type", "Type", FT_UINT16, BASE_DEC, (void*) VALS(this->mErrorTypeArray->data), 0x0);
    this->mFM.createField("err.code.hello", "Hello Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrHelloArray->data), 0x0);
    this->mFM.createField("err.code.badrq", "Bad Request Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrBadRqArray->data), 0x0);
    this->mFM.createField("err.code.badaction", "Bad Action Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrBadActionArray->data), 0x0);
    this->mFM.createField("err.code.fmfail", "Flow Mod Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrFMFailArray->data), 0x0);
    this->mFM.createField("err.code.gmfail", "Group Mod Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrGMFailArray->data), 0x0);
    this->mFM.createField("err.code.pmfail", "Port Mod Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrPMFailArray->data), 0x0);
    this->mFM.createField("err.code.tmfail", "Table Mod Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrTMFailArray->data), 0x0);
    this->mFM.createField("err.code.qofail", "Queue Operation Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrQOFailArray->data), 0x0);
    this->mFM.createField("err.code.scfail", "Switch Config Code", FT_UINT16, BASE_HEX, (void *) VALS(this->mErrSCFailArray->data), 0x0);
    this->mFM.createField("err.data", "Data", FT_STRING, BASE_NONE, NULL, 0x0);

    // Feature Request
    this->mFM.createField("featreq", "Feature Request", FT_NONE, BASE_NONE, NULL, 0x0);

    // Feature Reply
    this->mFM.createField("feat", "Feature Reply", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("feat.dpid", "Datapath ID", FT_UINT64, BASE_HEX, NULL, 0x0);
    this->mFM.createField("feat.buffers", "Buffers", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("feat.tables", "Tables", FT_UINT8, BASE_DEC, NULL, 0x0);

    this->mFM.createField("feat.cap", "Capabilities", FT_UINT32, BASE_HEX, NULL, 0x0, true);
    this->mFM.createField("feat.cap.reserved", "Reserved", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_RESERVED);
    this->mFM.createField("feat.cap.flowstats", "Flow Statistics", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_FLOWSTATS);
    this->mFM.createField("feat.cap.tablestats", "Table Statistics", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_TABLESTATS);
    this->mFM.createField("feat.cap.portstats", "Port Statistics", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_PORTSTATS);
    this->mFM.createField("feat.cap.groupstats", "Group Statistics", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_GROUPSTATS);
    this->mFM.createField("feat.cap.ipreasm", "IP Reassembly", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_IPREASM);
    this->mFM.createField("feat.cap.queuestats", "Queue Statistics", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_QUEUESTATS);
    this->mFM.createField("feat.cap.arpmatchip", "IP Match in ARP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), CAP_ARPMATCHIP);

    // Port
    this->mFM.createField("port", "Port Description", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("port.num", "Number", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("port.hwaddr", "Hardware Address", FT_ETHER, BASE_NONE, NULL, 0x0);
    this->mFM.createField("port.name", "Name", FT_STRING, BASE_NONE, NULL, 0x0);
    this->mFM.createField("port.config", "Config", FT_UINT32, BASE_DEC, NULL, 0x0, true);
    this->mFM.createField("port.state", "State", FT_UINT32, BASE_DEC, NULL, 0x0, true);
    this->mFM.createField("port.curr_feats", "Current Features", FT_UINT32, BASE_DEC, NULL, 0x0, true);
    this->mFM.createField("port.advertised", "Advertised Features", FT_UINT32, BASE_DEC, NULL, 0x0, true);
    this->mFM.createField("port.supported", "Supported Features", FT_UINT32, BASE_DEC, NULL, 0x0, true);
    this->mFM.createField("port.peer", "Peer Features", FT_UINT32, BASE_DEC, NULL, 0x0, true);
    this->mFM.createField("port.curr_speed", "Current Speed (kbps)", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("port.max_speed", "Maximum Speed (kbps)", FT_UINT32, BASE_DEC, NULL, 0x0);

    // OFPPC
    this->mFM.createField("ofppc.reserved", "Reserved", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPC_RESERVED);
    this->mFM.createField("ofppc.port_down", "Port Administratively Down", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPC_DOWN);
    this->mFM.createField("ofppc.no_recv", "Drop All Received Packets", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPC_NORECV);
    this->mFM.createField("ofppc.no_fwd", "Drop Packets Forwarded to Port", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPC_NOFWD);
    this->mFM.createField("ofppc.no_packet_in", "Do Not Send Packet-In Messages", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPC_NOPACKETIN);

    // OFPPS
    this->mFM.createField("ofpps.reserved", "Reserved", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPS_RESERVED);
    this->mFM.createField("ofpps.link_down", "Link Down", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPS_LINKDOWN);
    this->mFM.createField("ofpps.blocked", "Blocked", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPS_BLOCKED);
    this->mFM.createField("ofpps.live", "Live for Fast Failover", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPS_LIVE);

    // OFPPF
    this->mFM.createField("ofppf.10mbhd", "10 Mb Half Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_10MBHD);
    this->mFM.createField("ofppf.10mbfd", "10 Mb Full Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_10MBFD);
    this->mFM.createField("ofppf.100mbhd", "100 Mb Half Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_100MBHD);
    this->mFM.createField("ofppf.100mbfd", "100 Mb Full Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_100MBFD);
    this->mFM.createField("ofppf.1gbhd", "1 Gb Half Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_1GBHD);
    this->mFM.createField("ofppf.1gbfd", "1 Gb Full Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_1GBFD);
    this->mFM.createField("ofppf.10gbfd", "10 Gb Full Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_10GBFD);
    this->mFM.createField("ofppf.40gbfd", "40 Gb Full Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_40GBFD);
    this->mFM.createField("ofppf.100gbfd", "100 Gb Full Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_100GBFD);
    this->mFM.createField("ofppf.1tbfd", "1 Tb Full Duplex", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_1TBFD);
    this->mFM.createField("ofppf.ludicrous", "Ludicrous Speed", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_LUDICROUS);
    this->mFM.createField("ofppf.copper", "Copper", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_COPPER);
    this->mFM.createField("ofppf.fiber", "Fiber", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_FIBER);
    this->mFM.createField("ofppf.autoneg", "Auto-negotiation", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_AUTONEG);
    this->mFM.createField("ofppf.pause", "Pause", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_PAUSE);
    this->mFM.createField("ofppf.pause_asym", "Asymmetric Pause", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_PAUSEASYM);
    this->mFM.createField("ofppf.reserved", "Reserved", FT_BOOLEAN, 32, TFS(&tfs_set_notset), PPF_RESERVED);

    // Switch Config Reply
    this->mFM.createField("swtchconf", "Switch Configuration", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("swtchconf.flags", "Flags", FT_UINT16, BASE_DEC, NULL, 0x0, true);
    this->mFM.createField("swtchconf.flags.reserved", "Reserved", FT_BOOLEAN, 16, TFS(&tfs_set_notset), SCF_RESERVED);
    this->mFM.createField("swtchconf.flags.drop", "Fragments: Drop", FT_BOOLEAN, 16, TFS(&tfs_set_notset), SCF_DROP);
    this->mFM.createField("swtchconf.flags.reasm", "Fragments: Reassemble", FT_BOOLEAN, 16, TFS(&tfs_set_notset), SCF_REASM);
    this->mFM.createField("swtchconf.flags.invalid_ttl", "Send Invalid TTL to Controller", FT_BOOLEAN, 16, TFS(&tfs_set_notset), SCF_INVALIDTTL);
    this->mFM.createField("swtchconf.maxsendlen", "Max new flow bytes to controller", FT_UINT16, BASE_DEC, NULL, 0x0);

    // Flow Match
    this->mFM.createField("flow.match", "Match", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("flow.match.type", "Type", FT_UINT16, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.match.len", "Length", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.in_port", "In Port", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.wildcards", "Wildcards", FT_UINT32, BASE_HEX, NULL, 0x0, true);

    this->mFM.createField("flow.match.wc.reserved", "Reserved", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_RES);
    this->mFM.createField("flow.match.wc.inport", "In Port", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_INPORT);
    this->mFM.createField("flow.match.wc.vlan", "VLAN", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_VLAN);
    this->mFM.createField("flow.match.wc.vlanpcp", "VLAN PCP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_VLANPCP);
    this->mFM.createField("flow.match.wc.ethtype", "Ethertype", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_ETHTYPE);
    this->mFM.createField("flow.match.wc.ipdscp", "IP DSCP", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_IPDSCP);
    this->mFM.createField("flow.match.wc.ipproto", "IP Protocol", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_IPPROTO);
    this->mFM.createField("flow.match.wc.ipsrcp", "Source Port", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_IPSRCP);
    this->mFM.createField("flow.match.wc.ipdstp", "Dest Port", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_IPDSTP);
    this->mFM.createField("flow.match.wc.mplslbl", "MPLS Label", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_MPLSLBL);
    this->mFM.createField("flow.match.wc.mplstc", "MPLS TC", FT_BOOLEAN, 32, TFS(&tfs_set_notset), WC_FM_MPLSTC);

    /*FIXME: There's no BASE_BINARY, so FT_ETHER is how you're getting ethernet masks.  Have fun. */
    this->mFM.createField("flow.match.eth.src", "Ethernet Source Addr", FT_ETHER, BASE_NONE, NULL, 0x0);
    this->mFM.createField("flow.match.eth.src.mask", "Ethernet Source Mask", FT_ETHER, BASE_NONE, NULL, 0x0);
    this->mFM.createField("flow.match.eth.dst", "Ethernet Dest Addr", FT_ETHER, BASE_NONE, NULL, 0x0);
    this->mFM.createField("flow.match.eth.dst.mask", "Ethernet Dest Mask", FT_ETHER, BASE_NONE, NULL, 0x0);
    this->mFM.createField("flow.match.eth.vlan", "VLAN ID", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.eth.vlan.pcp", "VLAN Priority", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.eth.type", "Ethertype", FT_UINT16, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.match.ip.dscp", "IP DSCP", FT_UINT8, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.match.ip.proto", "IP Protocol", FT_UINT8, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.match.ip.src.addr", "IP Source Addr", FT_IPv4, BASE_NONE, NULL, 0x0);
    this->mFM.createField("flow.match.ip.src.mask", "IP Source Mask", FT_UINT32, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.match.ip.dst.addr", "IP Dest Addr", FT_IPv4, BASE_NONE, NULL, 0x0);
    this->mFM.createField("flow.match.ip.dst.mask", "IP Dest Mask", FT_UINT32, BASE_HEX, NULL, 0x0);
    /*FIXME: should really add individual entries for TCP/UDP/SCTP/whatever ports and switch on protocol */
    this->mFM.createField("flow.match.ip.src_port", "TCP/UDP Source Port", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.ip.dst_port", "TCP/UDP Dest Port", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.mpls.label", "MPLS Label", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.mpls.tc", "MPLS TC", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.match.metadata", "Metadata", FT_UINT64, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.match.metadata.mask", "Metadata Mask", FT_UINT64, BASE_HEX, NULL, 0x0);

    this->mFM.createField("flow.inst", "Instruction", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("flow.inst.type", "Type", FT_UINT16, BASE_HEX, VALS(this->mInstTypeArray->data), 0x0);
    this->mFM.createField("flow.inst.len", "Length", FT_UINT16, BASE_DEC, NULL, 0x0);

    this->mFM.createField("flow.inst.goto_table.table_id", "Table ID", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flow.inst.write_metadata.metadata", "Metadata", FT_UINT64, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.inst.write_metadata.metadata_mask", "Metadata Mask", FT_UINT64, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flow.inst.action", "Action", FT_NONE, BASE_NONE, NULL, 0x0, true);
    
    // Actions
    this->mFM.createField("action.type", "Type", FT_UINT16, BASE_HEX, NULL, 0x0);
    this->mFM.createField("action.len", "Length", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.output.port", "Port", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.output.max_len", "Max Length", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.group.id", "Group ID", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.set_queue.id", "Queue ID", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.set_vlan_vid.vid", "VLAN ID", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.set_vlan_pcp.prio", "VLAN Priority", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.set_mpls_label.label", "MPLS Label", FT_UINT32, BASE_HEX, NULL, 0x0);
    this->mFM.createField("action.set_mpls_tc.class", "MPLS TC", FT_UINT8, BASE_HEX, NULL, 0x0);
    this->mFM.createField("action.set_mpls_ttl.ttl", "MPLS TTL", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.set_dl_src.addr", "Address", FT_ETHER, BASE_NONE, NULL, 0x0);
    this->mFM.createField("action.set_dl_dst.addr", "Address", FT_ETHER, BASE_NONE, NULL, 0x0);
    this->mFM.createField("action.set_ipv4_src.addr", "Address", FT_IPv4, BASE_NONE, NULL, 0x0);
    this->mFM.createField("action.set_ipv4_dst.addr", "Address", FT_IPv4, BASE_NONE, NULL, 0x0);
    this->mFM.createField("action.set_ipv4_tos.tos", "TOS", FT_UINT8, BASE_HEX, NULL, 0x0);
    this->mFM.createField("action.set_ipv4_ecn.ecn", "ECN", FT_UINT8, BASE_HEX, NULL, 0x0);
    this->mFM.createField("action.set_ipv4_ttl.ttl", "TTL", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.set_tp_src_port.port", "Port", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.set_tp_dst_port.port", "Port", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("action.push.ethertype", "Ethertype", FT_UINT16, BASE_HEX, NULL, 0x0);
    this->mFM.createField("action.experimenter.id", "ID", FT_UINT32, BASE_HEX, NULL, 0x0);

    // Stats Request
    this->mFM.createField("statsrq", "Stats Request", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("statsrq.type", "Type", FT_UINT16, BASE_DEC, (void*) VALS(this->mStatsRqArray->data), 0x0);
    this->mFM.createField("statsrq.flags", "Flags", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrq.body", "Body", FT_NONE, BASE_NONE, NULL, 0x0, true);

    // Stats Reply
    this->mFM.createField("statsrp", "Stats Reply", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("statsrp.type", "Type", FT_UINT16, BASE_DEC, (void*) VALS(this->mStatsRpArray->data), 0x0);
    this->mFM.createField("statsrp.flags", "Flags", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrp.body", "Body", FT_NONE, BASE_NONE, NULL, 0x0, true);

    // Stats Flow Reply
    this->mFM.createField("statsrp.flow.len", "Length", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrp.flow.table", "Table ID", FT_UINT8, BASE_DEC, NULL, 0x0);
    /*FIXME: These two really should be one field with BASE_CUSTOM and a callback renderer */
    this->mFM.createField("statsrp.flow.duration.sec", "Duration (sec)", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrp.flow.duration.ns", "Duration (ns)", FT_UINT32, BASE_DEC, NULL, 0x0);

    this->mFM.createField("statsrp.flow.priority", "Priority", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrp.flow.tmt.idle", "Idle Timeout", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrp.flow.tmt.hard", "Hard Timeout", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrp.flow.cookie", "Cookie", FT_UINT64, BASE_HEX, NULL, 0x0);
    this->mFM.createField("statsrp.flow.count.packets", "Packet Count", FT_UINT64, BASE_DEC, NULL, 0x0);
    this->mFM.createField("statsrp.flow.count.bytes", "Byte Count", FT_UINT64, BASE_DEC, NULL, 0x0);

    // Port Status
    this->mFM.createField("pstatus", "Port Status", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("pstatus.reason", "Reason", FT_UINT8, BASE_HEX, (void *) VALS(this->mPortRTypeArray->data), 0x0);
    this->mFM.createField("pdesc", "Port Description", FT_NONE, BASE_NONE, NULL, 0x0, true);

    // Flow Mod
    this->mFM.createField("flowmod", "Flow Mod", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("flowmod.cookie", "Cookie", FT_UINT64, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flowmod.cookie.mask", "Cookie Mask", FT_UINT64, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flowmod.tableid", "Table ID", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flowmod.command", "Command", FT_UINT8, BASE_HEX, (void *) VALS(this->mFlowModCommandArray->data), 0x0);
    this->mFM.createField("flowmod.tmt.idle", "Idle Timeout", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flowmod.tmt.hard", "Hard Timeout", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flowmod.priority", "Priority", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flowmod.buf_id", "Buffer ID", FT_UINT32, BASE_HEX, NULL, 0x0);
    this->mFM.createField("flowmod.outport", "Output Port", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flowmod.outgroup", "Output Group", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("flowmod.flags", "Flags", FT_UINT16, BASE_HEX, NULL, 0x0);

    // Group Mod
    this->mFM.createField("groupmod", "Group Mod", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("groupmod.command", "Command", FT_UINT16, BASE_HEX, (void *) VALS(this->mGMCommandArray->data), 0x0);
    this->mFM.createField("groupmod.type", "Type", FT_UINT8, BASE_HEX, (void *) VALS(this->mGTArray->data), 0x0);
    this->mFM.createField("groupmod.groupid", "Group ID", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("groupmod.bucket", "Bucket", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("groupmod.bucket.len", "Length", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("groupmod.bucket.weight", "Weight", FT_UINT16, BASE_DEC, NULL, 0x0);
    this->mFM.createField("groupmod.bucket.watch_port", "Watch Port", FT_UINT32, BASE_DEC, NULL, 0x0);
    this->mFM.createField("groupmod.bucket.watch_group", "Watch Group", FT_UINT32, BASE_DEC, NULL, 0x0);

    // Table Mod
    this->mFM.createField("tblmod", "Table Mod", FT_NONE, BASE_NONE, NULL, 0x0, true);
    this->mFM.createField("tblmod.id", "ID", FT_UINT8, BASE_DEC, NULL, 0x0);
    this->mFM.createField("tblmod.config", "Config", FT_UINT32, BASE_HEX, NULL, 0x0, true);
    this->mFM.createField("tblmod.config.reserved", "Reserved", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TMC_RESERVED);
    this->mFM.createField("tblmod.config.miss_continue", "Miss: Continue", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TMC_MISS_CONTINUE);
    this->mFM.createField("tblmod.config.miss_drop", "Miss: Drop", FT_BOOLEAN, 32, TFS(&tfs_set_notset), TMC_MISS_DROP);
    }

  void
  DissectorContext::setupTypes (void)
    {
    // Message Types
    this->mTypeArray = g_array_new(FALSE, FALSE, sizeof (value_string));

    this->addType(0x00, "Hello (SM)");
    this->addType(0x01, "Error (SM)");
    this->addType(0x02, "Echo Request (SM)");
    this->addType(0x03, "Echo Reply (SM)");
    this->addType(0x04, "Experimenter (SM)");
    this->addType(0x05, "Features Request (CSM)");
    this->addType(0x06, "Features Reply (CSM)");
    this->addType(0x07, "Get Config Request (CSM)");
    this->addType(0x08, "Get Config Reply (CSM)");
    this->addType(0x09, "Set Config (CSM)");
    this->addType(0x0A, "Packet In (AM)");
    this->addType(0x0B, "Flow Removed (AM)");
    this->addType(0x0C, "Port Status (AM)");
    this->addType(0x0D, "Packet Out (CSM)");
    this->addType(0x0E, "Flow Mod (CSM)");
    this->addType(0x0F, "Group Mod (CSM)");
    this->addType(0x10, "Port Mod (CSM)");
    this->addType(0x11, "Table Mod (CSM)");
    this->addType(0x12, "Stats Request (CSM)");
    this->addType(0x13, "Stats Reply (CSM)");
    this->addType(0x14, "Barrier Request (CSM)");
    this->addType(0x15, "Barrier Reply (CSM)");
    this->addType(0x16, "Get Queue Config Request (CSM)");
    this->addType(0x17, "Get Queue Config Reply (CSM)");


    // Flow Mod Commands
    this->mFlowModCommandArray = g_array_new(FALSE, FALSE, sizeof(value_string));

    this->addFMCommand(0x00, "Add");
    this->addFMCommand(0x01, "Modify");
    this->addFMCommand(0x02, "Modify (Strict)");
    this->addFMCommand(0x03, "Delete");
    this->addFMCommand(0x04, "Delete (Strict)");

    // Instruction Types
    this->mInstTypeArray = g_array_new(FALSE, FALSE, sizeof(value_string));

    this->addInstType(0x01, "Goto Table");
    this->addInstType(0x02, "Write Metadata");
    this->addInstType(0x03, "Write Actions");
    this->addInstType(0x04, "Apply Actions");
    this->addInstType(0x05, "Clear Actions");
    }

  void
  DissectorContext::setupStatsTypes (void)
    {
    this->mStatsRqArray = g_array_new(FALSE, FALSE, sizeof(value_string));

    this->addStatsRqType(0x00, "Description");
    this->addStatsRqType(0x01, "Flow");
    this->addStatsRqType(0x02, "Aggregate Flow");
    this->addStatsRqType(0x03, "Flow Table");
    this->addStatsRqType(0x04, "Port");
    this->addStatsRqType(0x05, "Queue");
    this->addStatsRqType(0x06, "Group");
    this->addStatsRqType(0x07, "Group Description");
    this->addStatsRqType(0xFFFF, "Experimenter");

    this->mStatsRpArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addStatsRpType(0x00, "Description");
    this->addStatsRpType(0x01, "Flow");
    this->addStatsRpType(0x02, "Aggregate Flow");
    this->addStatsRpType(0x03, "Flow Table");
    this->addStatsRpType(0x04, "Port");
    this->addStatsRpType(0x05, "Queue");
    this->addStatsRpType(0x06, "Group");
    this->addStatsRpType(0x07, "Group Description");
    this->addStatsRpType(0xFFFF, "Experimenter");
    }

  void
  DissectorContext::setupErrorTypes (void)
    {
    this->mErrorTypeArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrorType(0x00, "Hello protocol failed (HELLO_FAILED)");
    this->addErrorType(0x01, "Request was not understood (BAD_REQUEST)");
    this->addErrorType(0x02, "Error in action description (BAD_ACTION)");
    this->addErrorType(0x03, "Problem modifying flow entry (FLOW_MOD_FAILED)");
    this->addErrorType(0x04, "Problem modifying group entry (GROUP_MOD_FAILED)");
    this->addErrorType(0x05, "Port mod request failed (PORT_MOD_FAILED)");
    this->addErrorType(0x06, "Table mod request failed (TABLE_MOD_FAILED)");
    this->addErrorType(0x07, "Queue operation failed (QUEUE_OP_FAILED)");
    this->addErrorType(0x08, "Switch config request failed (SWITCH_CONFIG_FAILED)");

    this->mErrHelloArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrHelloCode(0x00, "No compatible version (INCOMPATIBLE)");
    this->addErrHelloCode(0x01, "Permissions error (EPERM)");

    this->mErrBadRqArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrBadRequestCode(0x00, "Message version not supported (BAD_VERSION)");
    this->addErrBadRequestCode(0x01, "Message type not supported (BAD_TYPE)");
    this->addErrBadRequestCode(0x02, "Stats request type not supported (BAD_STAT)");
    this->addErrBadRequestCode(0x03, "Experimenter ID not suported (BAD_EXPERIMENTER)");
    this->addErrBadRequestCode(0x04, "Experimenter subtype not supported (BAD_SUBTYPE)");
    this->addErrBadRequestCode(0x05, "Permissions error (EPERM)");
    this->addErrBadRequestCode(0x06, "Wrong request length for type (BAD_LEN)");
    this->addErrBadRequestCode(0x07, "Specified buffer has already been used (BUFFER_EMPTY)");
    this->addErrBadRequestCode(0x08, "Specified buffer does not exist (BUFFER_UNKNOWN)");
    this->addErrBadRequestCode(0x09, "Specified table-id is invalid or does not exist (BAD_TABLE_ID)");

    this->mErrBadActionArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrBadActionCode(0x00, "Unknown action type (BAD_TYPE)");
    this->addErrBadActionCode(0x01, "Bad action length (BAD_LEN)");
    this->addErrBadActionCode(0x02, "Unknown experimenter ID (BAD_EXPERIMENTER)");
    this->addErrBadActionCode(0x03, "Unknown action type for experimenter (BAD_EXPERIMENTER_TYPE)");
    this->addErrBadActionCode(0x04, "Invalid output port (BAD_OUT_PORT)");
    this->addErrBadActionCode(0x05, "Bad action argument (BAD_ARGUMENT)");
    this->addErrBadActionCode(0x06, "Permissions error (EPERM)");
    this->addErrBadActionCode(0x07, "Can't handle this many actions (TOO_MANY)");
    this->addErrBadActionCode(0x08, "Invalid output queue (BAD_QUEUE)");
    this->addErrBadActionCode(0x09, "Invalid group ID in forward action (BAD_OUT_GROUP)");
    this->addErrBadActionCode(0x10, "Action can't apply for this match (MATCH_INCONSISTENT)");
    this->addErrBadActionCode(0x11, "Action order is unsupported for the action list in an Apply-Actions instruction (UNSUPPORTED_ORDER)");

    this->mErrFMFailArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrFMFailedCode(0x00, "Unspecified error (UNKNOWN)");
    this->addErrFMFailedCode(0x01, "Flow not added because table was full (TABLE_FULL)");
    this->addErrFMFailedCode(0x02, "Table does not exist (BAD_TABLE_ID)");
    this->addErrFMFailedCode(0x03, "Attempted to add overlapping flow with CHECK_OVERLAP flag set. (OVERLAP)");
    this->addErrFMFailedCode(0x04, "Permissions error (EPERM)");
    this->addErrFMFailedCode(0x05, "Flow not added because of unsupported idle/hard timeout (BAD_TIMEOUT)");
    this->addErrFMFailedCode(0x06, "Unsupported or unknown command (BAD_COMMAND)");
    this->addErrFMFailedCode(0x07, "Unsupported instruction specified (BAD_INSTRUCTION)");
    this->addErrFMFailedCode(0x08, "Unsupported match specified (BAD_MATCH)");
    this->addErrFMFailedCode(0x09, "Unsupported match type specified (BAD_MATCH_TYPE)");
    this->addErrFMFailedCode(0x10, "Instruction set uses an unsupported tag or encapsulation (BAD_TAG)");
    this->addErrFMFailedCode(0x11, "Unsupported datalink address mask (BAD_DL_ADDR_MASK)");
    this->addErrFMFailedCode(0x12, "Unsupported network address mask (BAD_NW_ADDR_MASK)");

    this->mErrGMFailArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrGMFailedCode(0x00, "Group not added because a group ADD attempted to replace an already present group (GROUP_EXISTS)");
    this->addErrGMFailedCode(0x01, "Group not added because specified group is invalid (INVALID_GROUP)");
    this->addErrGMFailedCode(0x02, "Switch does not support unequal load sharing between groups (WEIGHT_UNSUPPORTED)");
    this->addErrGMFailedCode(0x03, "Group table is full (OUT_OF_GROUPS)");
    this->addErrGMFailedCode(0x04, "The maximum number of action buckets for a group has been exceeded (OUT_OF_BUCKETS)");
    this->addErrGMFailedCode(0x05, "Switch does not support groups that forward to groups (CHAINING_UNSUPPORTED)");
    this->addErrGMFailedCode(0x06, "This group cannot watch the port or group specified (WATCH_UNSUPPORTED)");
    this->addErrGMFailedCode(0x07, "Group entry would cause a loop (LOOP)");
    this->addErrGMFailedCode(0x08, "Group not modified because specified group does not exist (UNKNOWN_GROUP)");

    this->mErrPMFailArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrPMFailedCode(0x00, "Specified port number does not exist (BAD_PORT)");
    this->addErrPMFailedCode(0x01, "Specified hardware address does not match port (BAD_HW_ADDR)");
    this->addErrPMFailedCode(0x02, "Specified config is invalid (BAD_CONFIG)");
    this->addErrPMFailedCode(0x03, "Specified advertise is invalid (BAD_ADVERTISE)");

    this->mErrTMFailArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrTMFailedCode(0x00, "Specified table does not exist (BAD_TABLE)");
    this->addErrTMFailedCode(0x01, "Specified config is invalid (BAD_CONFIG)");

    this->mErrQOFailArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrQOFailedCode(0x00, "Invalid port (BAD_PORT)");
    this->addErrQOFailedCode(0x01, "Queue does not exist (BAD_QUEUE)");
    this->addErrQOFailedCode(0x02, "Permissions error (EPERM)");

    this->mErrSCFailArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addErrSCFailedCode(0x00, "Specified flags are invalid (BAD_FLAGS)");
    this->addErrSCFailedCode(0x01, "Specified length is inavlid (BAD_LEN)");
    }

  void
  DissectorContext::setupPortReasonTypes (void)
    {
    this->mPortRTypeArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addPortReason(0x00, "Port was added (ADD)");
    this->addPortReason(0x01, "Port was removed (DELETE)");
    this->addPortReason(0x02, "Port attribute has changed (MODIFY)");
    }

  void
  DissectorContext::setupGroupModTypes (void)
    {
    this->mGMCommandArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addGMCommand(0x00, "Add");
    this->addGMCommand(0x01, "Modify");
    this->addGMCommand(0x02, "Delete");

    this->mGTArray = g_array_new(FALSE, FALSE, sizeof(value_string));
    this->addGroupType(0x00, "All (multicast/broadcast)");
    this->addGroupType(0x01, "Select");
    this->addGroupType(0x02, "Indirect");
    this->addGroupType(0x03, "Fast Failover");
    }

  void
  DissectorContext::addPortReason(guint32 value, const gchar *str)
    { this->addValueString(this->mPortRTypeArray, value, str); }

  void
  DissectorContext::addType (guint32 value, const gchar *str)
    { this->addValueString(this->mTypeArray, value, str); }

  void
  DissectorContext::addStatsRqType (guint32 value, const gchar *str)
    { this->addValueString(this->mStatsRqArray, value, str); }

  void
  DissectorContext::addStatsRpType (guint32 value, const gchar *str)
    { this->addValueString(this->mStatsRpArray, value, str); }

  void
  DissectorContext::addErrorType (guint32 value, const gchar *str)
    { this->addValueString(this->mErrorTypeArray, value, str); }

  void
  DissectorContext::addErrHelloCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrHelloArray, value, str); }

  void
  DissectorContext::addErrBadRequestCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrBadRqArray, value, str); }

  void
  DissectorContext::addErrBadActionCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrBadActionArray, value, str); }

  void
  DissectorContext::addErrFMFailedCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrFMFailArray, value, str); }

  void
  DissectorContext::addErrGMFailedCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrGMFailArray, value, str); }

  void
  DissectorContext::addErrPMFailedCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrPMFailArray, value, str); }

  void
  DissectorContext::addErrTMFailedCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrTMFailArray, value, str); }

  void
  DissectorContext::addErrQOFailedCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrQOFailArray, value, str); }

  void
  DissectorContext::addErrSCFailedCode (guint32 value, const gchar *str)
    { this->addValueString(this->mErrSCFailArray, value, str); }

  void
  DissectorContext::addFMCommand (guint32 value, const gchar *str)
    { this->addValueString(this->mFlowModCommandArray, value, str); }

  void
  DissectorContext::addInstType (guint32 value, const gchar *str)
    { this->addValueString(this->mInstTypeArray, value, str); }

  void
  DissectorContext::addGMCommand (guint32 value, const gchar *str)
    { this->addValueString(this->mGMCommandArray, value, str); }

  void
  DissectorContext::addGroupType (guint32 value, const gchar *str)
    { this->addValueString(this->mGTArray, value, str); }

  void
  DissectorContext::addValueString (GArray *array, guint32 value, const gchar *str)
    {
    value_string vs;
    memset(&vs, 0, sizeof vs);

    vs.value = value;
    vs.strptr = str;

    g_array_append_val(array, vs);
    }

  void
  DissectorContext::setHandles (dissector_handle_t data, dissector_handle_t openflow)
    {
    this->mDataHandle = data;
    this->mOpenflowHandle = openflow;
    }

  void
  DissectorContext::dissect (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
    {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, DissectorContext::getMessageLen, DissectorContext::prepDissect);
    }

  void
  DissectorContext::addChild (proto_item *tree, const char *key, guint32 len)
    {
    this->mFM.addItem(tree, key, this->_tvb, this->_offset, len);
    this->_offset += len;
    }

  void
  DissectorContext::addBoolean (proto_tree *tree, const char *key, guint32 len, guint32 value)
    {
    this->mFM.addBoolean(tree, key, this->_tvb, this->_offset, len, value);
    }

  void
  DissectorContext::consumeBytes (guint32 len)
    {
    this->_offset += len;
    }

  void
  DissectorContext::dispatchMessage (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
    {
    this->_offset = 0;
    this->_tvb = tvb;
    this->_pinfo = pinfo;
    this->_tree = tree;

    this->_rawLen = tvb_length_remaining(tvb, 0);
      
    guint8 type = tvb_get_guint8(this->_tvb, 1);
    this->_oflen = tvb_get_ntohs(this->_tvb, 2);

    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
      val_to_str(type, (value_string*) this->mTypeArray->data, "Unknown Type (0x%02x)"));

    if (this->_tree)
      {
      this->_curOFPSubtree = this->mFM.addSubtree(tree, "data", this->_tvb, 0, -1);
      proto_tree *hdr_tree = this->mFM.addSubtree(this->_curOFPSubtree, "header", this->_tvb, this->_offset, 8);

      this->addChild(hdr_tree, "ver", 1);
      this->addChild(hdr_tree, "type", 1);
      this->addChild(hdr_tree, "len", 2);
      this->addChild(hdr_tree, "xid", 4);

      if (this->_oflen > this->_rawLen)
        this->_oflen = this->_rawLen;

      if (this->_oflen > this->_offset)
        {
        switch (type)
          {
          case 0x01:
            this->dissectError();
            break;
          case 0x02:
          case 0x03:
            this->dissectEcho();
            break;
          case 0x05:
            this->dissectFeaturesRequest();
            break;
          case 0x06:
            this->dissectFeaturesReply();
            break;
          case 0x08:
          case 0x09:
            this->dissectGetSetConfig();
            break;
          case 0x0B:
            this->dissectFlowRemove();
            break;
          case 0x0C:
            this->dissectPortStatus();
            break;
          case 0x0E:
            this->dissectFlowMod();
            break;
          case 0x0F:
            this->dissectGroupMod();
            break;
          case 0x11:
            this->dissectTableMod();
            break;
          case 0x12:
            this->dissectStatsRequest();
            break;
          case 0x13:
            this->dissectStatsReply();
            break;
          case 0x07: // Get Config Request
          case 0x14: // Barrier Request
          case 0x15: // Barrier Reply
            break;
          default:
            this->_offset = this->_oflen;
          }
        }
      }
    }

  void
  DissectorContext::dissectError (void)
    {
    proto_tree *err_tree = this->mFM.addSubtree(this->_curOFPSubtree, "err", this->_tvb, this->_offset,
                                                this->_oflen - this->_offset); 

    this->addChild(err_tree, "err.type", 2);

    guint16 code = tvb_get_ntohs(this->_tvb, this->_offset);

    switch (code)
      {
      case 0x00:
        this->addChild(err_tree, "err.code.hello", 2);
        break;
      case 0x01:
        this->addChild(err_tree, "err.code.badrq", 2);
        break;
      case 0x02:
        this->addChild(err_tree, "err.code.badaction", 2);
        break;
      case 0x03:
        this->addChild(err_tree, "err.code.fmfail", 2);
        break;
      case 0x04:
        this->addChild(err_tree, "err.code.gmfail", 2);
        break;
      case 0x05:
        this->addChild(err_tree, "err.code.pmfail", 2);
        break;
      case 0x06:
        this->addChild(err_tree, "err.code.tmfail", 2);
        break;
      case 0x07:
        this->addChild(err_tree, "err.code.qofail", 2);
        break;
      case 0x08:
        this->addChild(err_tree, "err.code.scfail", 2);
        break;
      default:
        // Unknown type
        break;

      this->addChild(err_tree, "err.data", this->_oflen - this->_offset);
      }
    }

  void
  DissectorContext::dissectEcho (void)
    {
    this->addChild(this->_curOFPSubtree, "echo", this->_oflen - this->_offset);
    this->_offset = this->_oflen;
    }

  void
  DissectorContext::dissectFeaturesRequest (void)
    {
    this->addChild(this->_curOFPSubtree, "featreq", this->_oflen - this->_offset);
    }

  void
  DissectorContext::dissectFeaturesReply (void)
    {
    proto_tree *rp_tree = this->mFM.addSubtree(this->_curOFPSubtree, "feat", this->_tvb, this->_offset,
                                              this->_oflen - this->_offset);

    this->addChild(rp_tree, "feat.dpid", 8);
    this->addChild(rp_tree, "feat.buffers", 4);
    this->addChild(rp_tree, "feat.tables", 1);
    this->addChild(rp_tree, "pad", 3);

    guint32 capabilities = tvb_get_ntohl(this->_tvb, this->_offset);
    proto_tree *capt = this->mFM.addSubtree(rp_tree, "feat.cap", this->_tvb, this->_offset, 4);
    this->addBoolean(capt, "feat.cap.reserved", 4, capabilities);
    this->addBoolean(capt, "feat.cap.flowstats", 4, capabilities);
    this->addBoolean(capt, "feat.cap.tablestats", 4, capabilities);
    this->addBoolean(capt, "feat.cap.portstats", 4, capabilities);
    this->addBoolean(capt, "feat.cap.groupstats", 4, capabilities);
    this->addBoolean(capt, "feat.cap.ipreasm", 4, capabilities);
    this->addBoolean(capt, "feat.cap.queuestats", 4, capabilities);
    this->addBoolean(capt, "feat.cap.arpmatchip", 4, capabilities);
    this->consumeBytes(4);

    this->addChild(rp_tree, "pad", 4);

    // Ports
    guint32 portlen = this->_oflen - 32;
    if (portlen % 64 != 0)
      {
      // Packet alignment is off, we should probably complain
      }
    else
      {
      guint32 ports =  portlen / 64;
      for (int port = 0; port < ports; ++port)
        {
        this->dissectPort(rp_tree);
        }
      }
    }

  void
  DissectorContext::dissectGetSetConfig (void)
    {
    proto_tree *rp_tree = this->mFM.addSubtree(this->_curOFPSubtree, "swtchconf", this->_tvb, this->_offset,
                                               this->_oflen - this->_offset);

    guint16 flags = tvb_get_ntohs(this->_tvb, this->_offset);
    proto_tree *ft = this->mFM.addSubtree(rp_tree, "swtchconf.flags", this->_tvb, this->_offset, 2);
    this->addBoolean(ft, "swtchconf.flags.reserved", 2, flags);
    this->addBoolean(ft, "swtchconf.flags.normal", 2, flags);
    this->addBoolean(ft, "swtchconf.flags.drop", 2, flags);
    this->addBoolean(ft, "swtchconf.flags.reasm", 2, flags);
    this->addBoolean(ft, "swtchconf.flags.mask", 2, flags);
    this->addBoolean(ft, "swtchconf.flags.invalid_ttl", 2, flags);
    this->consumeBytes(2);

    this->addChild(rp_tree, "swtchconf.maxsendlen", 2);
    }

  void
  DissectorContext::dissectStatsRequest (void)
    {
    proto_tree *rq_tree = this->mFM.addSubtree(this->_curOFPSubtree, "statsrq", this->_tvb, this->_offset,
                                               this->_oflen - this->_offset);

    this->addChild(rq_tree, "statsrq.type", 2);
    this->addChild(rq_tree, "statsrq.flags", 2);
    this->addChild(rq_tree, "statsrq.body", this->_oflen - this->_offset);
    }

  void
  DissectorContext::dissectStatsReply (void)
    {
    proto_tree *rp_tree = this->mFM.addSubtree(this->_curOFPSubtree, "statsrp", this->_tvb, this->_offset,
                                               this->_oflen - this->_offset);

    guint16 type = tvb_get_ntohs(this->_tvb, this->_offset);

    this->addChild(rp_tree, "statsrp.type", 2);
    this->addChild(rp_tree, "statsrp.flags", 2);

    if (this->_oflen <= this->_offset)
      return;

    switch(type)
      {
      case 0x01:
        {
        proto_tree *bt = this->mFM.addSubtree(rp_tree, "statsrp.body", this->_tvb, this->_offset, 48);

        this->addChild(bt, "statsrp.flow.len", 2);
        this->addChild(bt, "statsrp.flow.table", 1);
        this->addChild(bt, "pad", 1);
        this->addChild(bt, "statsrp.flow.duration.sec", 4);
        this->addChild(bt, "statsrp.flow.duration.ns", 4);
        this->addChild(bt, "statsrp.flow.priority", 2);
        this->addChild(bt, "statsrp.flow.tmt.idle", 2);
        this->addChild(bt, "statsrp.flow.tmt.hard", 2);
        this->addChild(bt, "pad", 6);
        this->addChild(bt, "statsrp.flow.cookie", 8);
        this->addChild(bt, "statsrp.flow.count.packets", 8);
        this->addChild(bt, "statsrp.flow.count.bytes", 8);

        this->dissectFlowMatch(rp_tree);
        break;
        }
      default:
        this->addChild(rp_tree, "statsrp.body", this->_oflen - this->_offset);
        break;
      }
    }

  void
  DissectorContext::dissectFlowRemove (void)
    {
    }

  void
  DissectorContext::dissectPortStatus (void)
    {
    proto_tree *pt = this->mFM.addSubtree(this->_curOFPSubtree, "pstatus", this->_tvb, this->_offset,
                                  this->_oflen - this->_offset);

    this->addChild(pt, "pstatus.reason", 1);
    this->addChild(pt, "pad", 7);

    proto_tree *dt = this->mFM.addSubtree(pt, "pdesc", this->_tvb, this->_offset, this->_oflen - this->_offset);
    this->dissectPort(dt);
    }

  void
  DissectorContext::dissectFlowMod (void)
    {
    proto_tree *fmt = this->mFM.addSubtree(this->_curOFPSubtree, "flowmod", this->_tvb, this->_offset,
                                           this->_oflen - this->_offset);

    this->addChild(fmt, "flowmod.cookie", 8);
    this->addChild(fmt, "flowmod.cookie.mask", 8);
    this->addChild(fmt, "flowmod.tableid", 1);
    this->addChild(fmt, "flowmod.command", 1);
    this->addChild(fmt, "flowmod.tmt.idle", 2);
    this->addChild(fmt, "flowmod.tmt.hard", 2);
    this->addChild(fmt, "flowmod.priority", 2);
    this->addChild(fmt, "flowmod.buf_id", 4);
    this->addChild(fmt, "flowmod.outport", 4);
    this->addChild(fmt, "flowmod.outgroup", 4);
    this->addChild(fmt, "flowmod.flags", 2);
    this->addChild(fmt, "pad", 2);

    this->dissectFlowMatch(fmt);

    try
      {
      while ((this->_oflen - this->_offset) > 0)
        {
        this->dissectInstruction(fmt);
        }
      }
    catch (const ZeroLenInstruction &e)
      {
      return;
      }
    }

  void
  DissectorContext::dissectGroupMod (void)
    {
    proto_tree *t = this->mFM.addSubtree(this->_curOFPSubtree, "groupmod", this->_tvb, this->_offset,
                                         this->_oflen - this->_offset);

    this->addChild(t, "groupmod.command", 2);
    this->addChild(t, "groupmod.type", 1);
    this->addChild(t, "pad", 1);
    this->addChild(t, "groupmod.groupid", 4);

    try
      {
      while((this->_oflen - this->_offset) > 0)
        {
        this->dissectGroupBucket(t);
        }
      }
    catch (const ZeroLenBucket &e)
      {
      return;
      }
    }

  void
  DissectorContext::dissectTableMod (void)
    {
    proto_tree *t = this->mFM.addSubtree(this->_curOFPSubtree, "tblmod", this->_tvb, this->_offset,
                                         this->_oflen - this->_offset);

    this->addChild(t, "tblmod.id", 1);
    this->addChild(t, "pad", 3);

    guint32 config = tvb_get_ntohl(this->_tvb, this->_offset);
    proto_tree *c = this->mFM.addSubtree(t, "tblmod.config", this->_tvb, this->_offset, 4);
    this->addBoolean(c, "tblmod.config.reserved", 4, config);
    this->addBoolean(c, "tblmod.config.miss_continue", 4, config);
    this->addBoolean(c, "tblmod.config.miss_drop", 4, config);
    this->consumeBytes(4);
    }

  void
  DissectorContext::dissectPort (proto_tree *tree)
    {
    proto_tree *t = this->mFM.addSubtree(tree, "port", this->_tvb, this->_offset, 64);

    this->addChild(t, "port.num", 4);
    this->addChild(t, "pad", 4);
    this->addChild(t, "port.hwaddr", 6);
    this->addChild(t, "pad", 2);
    this->addChild(t, "port.name", 16);

    this->dissectOFPPC(t, "port.config");
    this->dissectOFPPS(t, "port.state");
    this->dissectOFPPF(t, "port.curr_feats");
    this->dissectOFPPF(t, "port.advertised");
    this->dissectOFPPF(t, "port.supported");
    this->dissectOFPPF(t, "port.peer");

    this->addChild(t, "port.curr_speed", 4);
    this->addChild(t, "port.max_speed", 4);
    }

  void
  DissectorContext::dissectOFPPC (proto_tree *tree, std::string key)
    {
    proto_tree *t = this->mFM.addSubtree(tree, key, this->_tvb, this->_offset, 4);

    guint32 ofppc = tvb_get_ntohl(this->_tvb, this->_offset);
    this->addBoolean(t, "ofppc.reserved", 4, ofppc);
    this->addBoolean(t, "ofppc.port_down", 4, ofppc);
    this->addBoolean(t, "ofppc.no_recv", 4, ofppc);
    this->addBoolean(t, "ofppc.no_fwd", 4, ofppc);
    this->addBoolean(t, "ofppc.no_packet_in", 4, ofppc);
    this->consumeBytes(4);
    }

  void
  DissectorContext::dissectOFPPS (proto_tree *tree, std::string key)
    {
    proto_tree *t = this->mFM.addSubtree(tree, key, this->_tvb, this->_offset, 4);

    guint32 ofpps = tvb_get_ntohl(this->_tvb, this->_offset);
    this->addBoolean(t, "ofpps.reserved", 4, ofpps);
    this->addBoolean(t, "ofpps.link_down", 4, ofpps);
    this->addBoolean(t, "ofpps.blocked", 4, ofpps);
    this->addBoolean(t, "ofpps.live", 4, ofpps);
    this->consumeBytes(4);
    }

  void
  DissectorContext::dissectOFPPF (proto_tree *tree, std::string key)
    {
    proto_tree *t = this->mFM.addSubtree(tree, key, this->_tvb, this->_offset, 4);

    guint32 ofppf = tvb_get_ntohl(this->_tvb, this->_offset);
    this->addBoolean(t, "ofppf.reserved", 4, ofppf);
    this->addBoolean(t, "ofppf.10mbhd", 4, ofppf);
    this->addBoolean(t, "ofppf.10mbfd", 4, ofppf);
    this->addBoolean(t, "ofppf.100mbhd", 4, ofppf);
    this->addBoolean(t, "ofppf.100mbfd", 4, ofppf);
    this->addBoolean(t, "ofppf.1gbhd", 4, ofppf);
    this->addBoolean(t, "ofppf.1gbfd", 4, ofppf);
    this->addBoolean(t, "ofppf.10gbfd", 4, ofppf);
    this->addBoolean(t, "ofppf.40gbfd", 4, ofppf);
    this->addBoolean(t, "ofppf.100gbfd", 4, ofppf);
    this->addBoolean(t, "ofppf.1tbfd", 4, ofppf);
    this->addBoolean(t, "ofppf.ludicrous", 4, ofppf);
    this->addBoolean(t, "ofppf.copper", 4, ofppf);
    this->addBoolean(t, "ofppf.fiber", 4, ofppf);
    this->addBoolean(t, "ofppf.autoneg", 4, ofppf);
    this->addBoolean(t, "ofppf.pause", 4, ofppf);
    this->addBoolean(t, "ofppf.pause_asym", 4, ofppf);
    this->consumeBytes(4);
    }

  void
  DissectorContext::dissectFlowMatch (proto_tree *tree)
    {
    proto_tree *t = this->mFM.addSubtree(tree, "flow.match", this->_tvb, this->_offset, this->_oflen - this->_offset);

#define CHECK_WILDCARD(m,t,f,l) \
    if (wildcards & (m)) \
      this->consumeBytes(l); \
    else \
      this->addChild(t,f,l);

    /*FIXME: We should care if the type isn't STANDARD (0x00) */

    // We're going to grab the wildcards so we can selectively display info in the tree
    // CHECK_WILDCARD requires this local to exist
    guint32 wildcards = tvb_get_ntohl(this->_tvb, this->_offset + 8);

    this->addChild(t, "flow.match.type", 2);
    this->addChild(t, "flow.match.len", 2);

    CHECK_WILDCARD(WC_FM_INPORT, t, "flow.match.in_port", 4);

    // This creates the wildcards as the standard bit-tree view in the UI
    proto_tree *wct = this->mFM.addSubtree(t, "flow.match.wildcards", this->_tvb, this->_offset, 4);
    this->addBoolean(wct, "flow.match.wc.reserved", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.inport", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.vlan", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.vlanpcp", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.ethtype", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.ipdscp", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.ipproto", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.ipsrcp", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.ipdstp", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.mplslbl", 4, wildcards);
    this->addBoolean(wct, "flow.match.wc.mplstc", 4, wildcards);

    // Adding booleans doesn't consume the bits, so we need to move the offset the length of the wildcard field
    this->consumeBytes(4);

    this->addChild(t, "flow.match.eth.src", 6);
    this->addChild(t, "flow.match.eth.src.mask", 6);
    this->addChild(t, "flow.match.eth.dst", 6);
    this->addChild(t, "flow.match.eth.dst.mask", 6);

    CHECK_WILDCARD(WC_FM_VLAN, t, "flow.match.eth.vlan", 2);
    CHECK_WILDCARD(WC_FM_VLANPCP, t, "flow.match.eth.vlan.pcp", 1);
    this->addChild(t, "pad", 1);
    CHECK_WILDCARD(WC_FM_ETHTYPE, t, "flow.match.eth.type", 2);
    CHECK_WILDCARD(WC_FM_IPDSCP, t, "flow.match.ip.dscp", 1);
    CHECK_WILDCARD(WC_FM_IPPROTO, t, "flow.match.ip.proto", 1);

    this->addChild(t, "flow.match.ip.src.addr", 4);
    this->addChild(t, "flow.match.ip.src.mask", 4);
    this->addChild(t, "flow.match.ip.dst.addr", 4);
    this->addChild(t, "flow.match.ip.dst.mask", 4);

    CHECK_WILDCARD(WC_FM_IPSRCP, t, "flow.match.ip.src_port", 2);
    CHECK_WILDCARD(WC_FM_IPDSTP, t, "flow.match.ip.dst_port", 2);
    CHECK_WILDCARD(WC_FM_MPLSLBL, t, "flow.match.mpls.label", 4);
    CHECK_WILDCARD(WC_FM_MPLSTC, t, "flow.match.mpls.tc", 1);
    this->addChild(t, "pad", 3);

    this->addChild(t, "flow.match.metadata", 8);
    this->addChild(t, "flow.match.metadata.mask", 8);
    }

  void
  DissectorContext::dissectInstruction (proto_tree *parent)
    {
    guint16 type = tvb_get_ntohs(this->_tvb, this->_offset);
    guint16 len = tvb_get_ntohs(this->_tvb, this->_offset+2);

    guint32 message_end = this->_offset + len;

    if (len == 0)
      { throw ZeroLenInstruction(); }
    else
      { /* std::cout << "Found instruction with length: " << len << std::endl; */ }

    proto_tree *t = this->mFM.addSubtree(parent, "flow.inst", this->_tvb, this->_offset, len);
    this->addChild(t, "flow.inst.type", 2);
    this->addChild(t, "flow.inst.len", 2);

    switch (type)
      {
      case 1: // GOTO_TABLE
          {
          this->addChild(t, "flow.inst.goto_table.table_id", 1);
          this->addChild(t, "pad", 3);
          break;
          }
      case 2: // WRITE_METADATA
          {
          this->addChild(t, "pad", 4);
          this->addChild(t, "flow.inst.write_metadata.metadata", 8);
          this->addChild(t, "flow.inst.write_metadata.metadata_mask", 8);
          break;
          }
      case 3: // WRITE_ACTIONS
      case 4: // APPLY_ACTIONS
          {
          try
            {
            while (this->_offset < message_end)
              {
              this->dissectAction(t);
              } 
            }
          catch (const ZeroLenAction &e)
            {
            break;
            }
          break;
          }
      case 5: // CLEAR_ACTIONS
          {
          this->addChild(t, "pad", 4);
          break;
          }
      default:
          {
          // Unknown type
          this->consumeBytes(message_end - this->_offset);
          }
      }
    }

  void
  DissectorContext::dissectAction (proto_tree *parent)
    {
    guint16 type = tvb_get_ntohs(this->_tvb, this->_offset);
    guint16 len = tvb_get_ntohs(this->_tvb, this->_offset+2);

    if (len == 0)
      { throw ZeroLenAction(); }

    guint32 message_end = this->_offset + len;

    proto_tree *t = this->mFM.addSubtree(parent, "flow.inst.action", this->_tvb, this->_offset, len);
    this->addChild(t, "action.type", 2);
    this->addChild(t, "action.len", 2);

    switch (type)
      {
      case 0x00: // OUTPUT
        this->addChild(t, "action.output.port", 4);
        this->addChild(t, "action.output.max_len", 2);
        this->addChild(t, "pad", 6);
        break;
      case 0x01: // SET_VLAN_VID
        this->addChild(t, "action.set_vlan_vid.vid", 2);
        this->addChild(t, "pad", 2);
        break;
      case 0x02: // SET_VLAN_PCP
        this->addChild(t, "action.set_vlan_pcp.prio", 1);
        this->addChild(t, "pad", 3);
        break;
      case 0x03: // SET_DL_SRC
        this->addChild(t, "action.set_dl_src.addr", 6);
        this->addChild(t, "pad", 6);
        break;
      case 0x04: // SET_DL_DST
        this->addChild(t, "action.set_dl_dst.addr", 6);
        this->addChild(t, "pad", 6);
        break;
      case 0x05: // SET_NW_SRC
        this->addChild(t, "action.set_ipv4_src.addr", 4);
        break;
      case 0x06: // SET_NW_DST
        this->addChild(t, "action.set_ipv4_dst.addr", 4);
        break;
      case 0x07: // SET_NW_TOS
        this->addChild(t, "action.set_ipv4_tos.tos", 1);
        this->addChild(t, "pad", 3);
        break;
      case 0x08: // SET_NW_ECN
        this->addChild(t, "action.set_ipv4_ecn.ecn", 1);
        this->addChild(t, "pad", 3);
        break;
      case 0x09: // SET_TP_SRC
        this->addChild(t, "action.set_tp_src_port.port", 2);
        this->addChild(t, "pad", 2);
        break;
      case 0x0A: // SET_TP_DST
        this->addChild(t, "action.set_tp_dst_port.port", 2);
        this->addChild(t, "pad", 2);
        break;
      case 0x0B: // COPY_TTL_OUT
      case 0x0C: // COPY_TTL_IN
        this->addChild(t, "pad", 4);
      case 0x0D: // SET_MPLS_LABEL
        this->addChild(t, "action.set_mpls_label.label", 4);
        break;
      case 0x0E: // SET_MPLS_TC
        this->addChild(t, "action.set_mpls_tc.class", 1);
        this->addChild(t, "pad", 3);
        break;
      case 0x0F: // SET_MPLS_TTL
        this->addChild(t, "action.set_mpls_ttl.ttl", 1);
        this->addChild(t, "pad", 3);
        break;
      case 0x18: // DEC_NW_TTL
      case 0x10: // DEC_MPLS_TTL
        this->addChild(t, "pad", 4);
        break;
      case 0x11: // PUSH_VLAN
      case 0x13: // PUSH_MPLS
        this->addChild(t, "action.push.ethertype", 2);
        this->addChild(t, "pad", 2);
        break;
      case 0x12: // POP_VLAN
      case 0x14: // POP_MPLS
        this->addChild(t, "pad", 4);
        break;
      case 0x15: // SET_QUEUE
        this->addChild(t, "action.set_queue.id", 4);
        break;
      case 0x16: // GROUP
        this->addChild(t, "action.group.id", 4);
        break;
      case 0x17: // SET_NW_TTL
        this->addChild(t, "action.set_ipv5_ttl.ttl", 1);
        this->addChild(t, "pad", 3);
        break;
      case 0xFFFF: // EXPERIMENTER
        this->addChild(t, "action.experimenter.id", 4);
        break;
      default:
        this->consumeBytes(message_end - this->_offset);
        break;
      }
    }

  void
  DissectorContext::dissectGroupBucket (proto_tree *pt)
    {
    guint16 len = tvb_get_ntohs(this->_tvb, this->_offset);

    if (len == 0)
      { throw ZeroLenBucket(); }

    guint32 message_end = this->_offset + len;

    proto_tree *t = this->mFM.addSubtree(pt, "groupmod.bucket", this->_tvb, this->_offset, len);
    this->addChild(t, "groupmod.bucket.len", 2);
    this->addChild(t, "groupmod.bucket.weight", 2);
    this->addChild(t, "groupmod.bucket.watch_port", 4);
    this->addChild(t, "groupmod.bucket.watch_group", 4);
    this->addChild(t, "pad", 4);

    try
      {
      while (this->_offset < message_end)
        {
        this->dissectAction(t);
        }
      }
    catch(const ZeroLenAction &e)
      {
      return;
      }
    }

  guint
  DissectorContext::getMessageLen (packet_info *pinfo, tvbuff_t *tvb, int offset)
    {
    // 0-7    version
    // 8-15   type
    // 16-31  length
    return (guint) tvb_get_ntohs(tvb, offset+2);
    }

  void
  DissectorContext::prepDissect (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
    {
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_OPENFLOW_VER);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);

    Context->dispatchMessage(tvb, pinfo, tree);
    }

  DissectorContext *
  DissectorContext::getInstance (int proto_openflow)
    {
    if (mSingle == NULL)
      {
      mSingle = new DissectorContext(proto_openflow);
      }

    return mSingle;
    }

  void
  init (int proto_openflow)
    {
    DissectorContext::getInstance(proto_openflow);
    }
  }
