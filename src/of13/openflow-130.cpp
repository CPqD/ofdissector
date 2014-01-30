/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University
Copyright (c) 2012 Barnstormer Softworks Ltd.
Copyright (c) 2012 CPqD */

#define OPENFLOW_INTERNAL

#include <string.h>
#include <iostream>
#include <of13/openflow-130.hpp>
#include <openflow-common.hpp>
#include "openflow/of13.h"


#include <stdio.h>

#if defined(__cplusplus)
extern "C" {
    #endif

    #include <epan/dissectors/packet-tcp.h>
    #include <epan/value_string.h>

    #if defined(__cplusplus)
}
#endif

// Exceptions
class ZeroLenInstruction { };
class ZeroLenAction { };
class ZeroLenBucket { };

// OFP utils
/* Fill an oxm_header */
#define OXM_HEADER(class, field, hasmask, length) \
    ((class << 16) | (field << 9) | (hasmask << 8) | (length/8))
/* Get the padding needed for some structs */
#define OFP_MATCH_OXM_PADDING(length) \
    ((length + 7)/8*8 - length)
#define OFP_ACTION_SET_FIELD_OXM_PADDING(oxm_len) \
    (((oxm_len + 4) + 7)/8*8 - (oxm_len + 4))
/* Extract fields from an oxm_header */
#define UNPACK_OXM_VENDOR(header) (header >> 16)
#define UNPACK_OXM_FIELD(header) ((header >> 9) & 0x0000007F)
#define UNPACK_OXM_HASMASK(header) ((header >> 8) & 0x00000001)
#define UNPACK_OXM_LENGTH(header) (header & 0x000000FF)


/* WARNING: Yep, macros can be evil when used this way, but they are here
because they simplified the development in this case. In the future, we will
try to get rid of them through a different API in FieldManager and new
functions and methods. */

/* Create a type array, used to map codes to values */
#define TYPE_ARRAY(name) this->name = g_array_new(FALSE, FALSE, sizeof (value_string))
/* Maps a value code to a string value */
#define TYPE_ARRAY_ADD(array, value, str) addValueString(this->array, value, str)

/* Create a tree structure for a given field in variable name */
#define ADD_TREE(name, field) \
    proto_tree* name = this->mFM.addSubtree(this->_curOFPSubtree, field, this->_tvb, this->_offset, this->_oflen - this->_offset)
/* Create a subtree structure with a given parent and length in a variable name */
#define ADD_SUBTREE(name, parent, field, length) \
    proto_tree* name = this->mFM.addSubtree(parent, field, this->_tvb, this->_offset, length)

/* Read values in network order */
#define READ_UINT16(name) \
    guint16 name = tvb_get_ntohs(this->_tvb, this->_offset)
#define READ_UINT32(name) \
    guint32 name = tvb_get_ntohl(this->_tvb, this->_offset)

/* Adds fields to a tree */
#define ADD_BOOLEAN(tree, field, length, bitmap) \
    this->mFM.addBoolean(tree, field, this->_tvb, this->_offset, length, bitmap)
#define ADD_CHILD(tree, field, length) \
    this->mFM.addItem(tree, field, this->_tvb, this->_offset, length); this->_offset += length
#define ADD_DISSECTOR(tree, field, length)	\
    this->mFM.addDissector(tree, field, this->_tvb, this->_pinfo, this->_ether_handle, this->_offset, length); this->_offset += length
#define CONSUME_BYTES(length) \
    this->_offset += length

/*  Values based on type arrays and masks */
#define VALUES(array) (void *) VALS(this->array->data)
#define NO_VALUES NULL
#define NO_MASK 0x0
/* A tree field contains one or more children fields */
#define TREE_FIELD(key, desc) \
    this->mFM.createField(key, desc, FT_NONE, BASE_NONE, NO_VALUES, NO_MASK, true)
#define FIELD(key, desc, type, base, values, mask) \
    this->mFM.createField(key, desc, type, base, values, mask, false)
/* A bitmap field is a tree containing several bitmap parts */
#define BITMAP_FIELD(field, desc, type) \
    this->mFM.createField(field, desc, type, BASE_HEX, NO_VALUES, NO_MASK, true)
#define BITMAP_PART(field, desc, length, mask) \
    this->mFM.createField(field, desc, FT_BOOLEAN, length, TFS(&tfs_set_notset), mask, false)

#define SHOW_ERROR(where, msg) expert_add_info_format(this->_pinfo, where, PI_MALFORMED, PI_ERROR, msg)


namespace openflow_130 {

DissectorContext * DissectorContext::mSingle = NULL;
DissectorContext * Context;

DissectorContext * DissectorContext::getInstance (int proto_openflow) {
    if (mSingle == NULL) {
        mSingle = new DissectorContext(proto_openflow);
    }

    return mSingle;
}

void DissectorContext::setHandles (dissector_handle_t data, dissector_handle_t openflow) {
    this->mDataHandle = data;
    this->mOpenflowHandle = openflow;
}

void DissectorContext::prepDissect (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_OPENFLOW_VER);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);

    Context->dispatchMessage(tvb, pinfo, tree);
}

void DissectorContext::dissect (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, DissectorContext::getMessageLen, DissectorContext::prepDissect);
}

guint DissectorContext::getMessageLen(packet_info *pinfo, tvbuff_t *tvb, int offset) {
    // 0-7    version
    // 8-15   type
    // 16-31  length
    return (guint) tvb_get_ntohs(tvb, offset + 2);
}

void init(int proto_openflow) {
    DissectorContext::getInstance(proto_openflow);
}

DissectorContext::DissectorContext (int proto_openflow) : mProtoOpenflow(proto_openflow), mFM(proto_openflow, "of13") {
    Context = this;

    this->_ether_handle = find_dissector("eth_withoutfcs");
    this->setupCodes();
    this->setupFlags();
    this->setupFields();

    this->mFM.doRegister();
}

void DissectorContext::dispatchMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    this->_offset = 0;
    this->_tvb = tvb;
    this->_pinfo = pinfo;
    this->_tree = tree;

    this->_rawLen = tvb_length_remaining(tvb, 0);

    guint8 type = tvb_get_guint8(this->_tvb, 1);
    this->_oflen = tvb_get_ntohs(this->_tvb, 2);

    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(type, (value_string*) this->ofp_type->data, "Unknown Type (0x%02x)"));

    if (this->_tree) {
        this->_curOFPSubtree = this->mFM.addSubtree(tree, "data", this->_tvb, 0, -1);
        proto_tree *hdr_tree = this->mFM.addSubtree(this->_curOFPSubtree, "ofp_header", this->_tvb, this->_offset, 8);

        ADD_CHILD(hdr_tree, "ofp_header.version", 1);
        ADD_CHILD(hdr_tree, "ofp_header.type", 1);
        ADD_CHILD(hdr_tree, "ofp_header.length", 2);
        ADD_CHILD(hdr_tree, "ofp_header.xid", 4);

        if (this->_oflen > this->_rawLen)
            this->_oflen = this->_rawLen;

        #define IGNORE this->_offset = this->_oflen
        if (this->_oflen > this->_offset) {
            switch (type) {
                case OFPT_HELLO:
                    IGNORE; // Nothing to parse
                    break;

                case OFPT_ERROR:
                    this->dissect_ofp_error();
                    break;

                case OFPT_ECHO_REQUEST:
                case OFPT_ECHO_REPLY:
                    this->dissect_ofp_echo();

                case OFPT_EXPERIMENTER:
                    IGNORE; // We don't know how to dissect
                    break;

                case OFPT_FEATURES_REQUEST:
                    this->dissectFeaturesRequest();
                    break;

                case OFPT_FEATURES_REPLY:
                    this->dissect_ofp_switch_features();
                    break;

                case OFPT_GET_CONFIG_REQUEST:
                    break;

                case OFPT_GET_CONFIG_REPLY:
                case OFPT_SET_CONFIG:
                    this->dissect_ofp_switch_config();
                    break;

                case OFPT_PACKET_IN:
                    this->dissect_ofp_packet_in();
                    break;

                case OFPT_FLOW_REMOVED:
                    IGNORE; // Not yet implemented
                    break;

                case OFPT_PORT_STATUS:
                    this->dissect_ofp_portStatus();
                    break;

                case OFPT_PACKET_OUT:
                    this->dissect_ofp_packet_out();
                    break;

                case OFPT_FLOW_MOD:
                    this->dissect_ofp_flow_mod();
                    break;

                case OFPT_GROUP_MOD:
                    this->dissectGroupMod();
                    break;

                case OFPT_PORT_MOD:
                    this->dissect_ofp_port_mod();
                    break;

                case OFPT_TABLE_MOD:
                    this->dissect_ofp_table_mod();
                    break;

                case OFPT_MULTIPART_REQUEST:
                    this->dissect_ofp_multipart_request();
                    break;

                case OFPT_MULTIPART_REPLY:
                    this->dissect_ofp_multipart_reply();
                    break;

                case OFPT_BARRIER_REQUEST:
                case OFPT_BARRIER_REPLY:
                    break;

                case OFPT_QUEUE_GET_CONFIG_REQUEST:
                case OFPT_QUEUE_GET_CONFIG_REPLY:
                    IGNORE; // Not yet implemented
                    break;

                case OFPT_ROLE_REQUEST:
                case OFPT_ROLE_REPLY:
                    this->dissect_ofp_role_request();
                    break;

                case OFPT_GET_ASYNC_REPLY:
                case OFPT_SET_ASYNC:
                    this->dissect_ofp_get_async_reply();
                    break;

                case OFPT_METER_MOD:
                    this->dissect_ofp_meter_mod();
                    break;

                default:
                    IGNORE; // We don't know what to do
            }
        }
    }
}

// Dissection methods
void DissectorContext::dissect_ofp_echo() {
    ADD_CHILD(this->_curOFPSubtree, "echo", this->_oflen - this->_offset);
    this->_offset = this->_oflen;
}

void DissectorContext::dissect_ofp_error() {
    ADD_TREE(tree, "ofp_error");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_error.type", 2);

    #define STR(a) #a
    #define ERROR(value) \
    case value: \
        ADD_CHILD(tree, STR(ofp_error.code.value), 2); \
        break;
    // TODO: this can improve...
    switch (type) {
        ERROR(OFPET_HELLO_FAILED)
        ERROR(OFPET_BAD_REQUEST)
        ERROR(OFPET_BAD_ACTION)
        ERROR(OFPET_BAD_INSTRUCTION)
        ERROR(OFPET_BAD_MATCH)
        ERROR(OFPET_FLOW_MOD_FAILED)
        ERROR(OFPET_GROUP_MOD_FAILED)
        ERROR(OFPET_PORT_MOD_FAILED)
        ERROR(OFPET_TABLE_MOD_FAILED)
        ERROR(OFPET_QUEUE_OP_FAILED)
        ERROR(OFPET_SWITCH_CONFIG_FAILED)
        ERROR(OFPET_ROLE_REQUEST_FAILED)
        ERROR(OFPET_EXPERIMENTER)
        default:
            break;
    }

    ADD_CHILD(tree, "ofp_error.data", this->_oflen - this->_offset);
}

void DissectorContext::dissectFeaturesRequest() {
    ADD_CHILD(this->_curOFPSubtree, "featreq", this->_oflen - this->_offset);
}

void DissectorContext::dissect_ofp_switch_features() {
    ADD_TREE(tree, "ofp_switch_features");

    ADD_CHILD(tree, "ofp_switch_features.datapath_id", 8);
    ADD_CHILD(tree, "ofp_switch_features.n_buffers", 4);
    ADD_CHILD(tree, "ofp_switch_features.n_tables", 1);
    ADD_CHILD(tree, "ofp_switch_features.auxiliary_id", 1);
    ADD_CHILD(tree, "padding", 2);

    READ_UINT32(capabilities);
    ADD_SUBTREE(capabilities_tree, tree, "ofp_switch_features.capabilities", 4);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.RESERVED", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_FLOW_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_TABLE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_PORT_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_GROUP_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_IP_REASM", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_QUEUE_STATS", 4, capabilities);
    ADD_BOOLEAN(capabilities_tree, "ofp_capabilities.OFPC_PORT_BLOCKED", 4, capabilities);
    CONSUME_BYTES(4);

    ADD_CHILD(tree, "ofp_switch_features.reserved", 4);
}

void DissectorContext::dissect_ofp_switch_config() {
    ADD_TREE(tree, "ofp_switch_config");

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_switch_config.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_config_flags.RESERVED", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_FRAG_DROP", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_FRAG_REASM", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_config_flags.OFPC_INVALID_TTL_TO_CONTROLLER", 2, flags);
    CONSUME_BYTES(2);

    ADD_CHILD(tree, "ofp_switch_config.miss_send_len", 2);
}

void DissectorContext::dissect_ofp_table_feature_prop(proto_tree* parent) {
    READ_UINT16(type);
    this->_offset += 2; // read ahead
    READ_UINT16(length);
    this->_offset -= 2;

    ADD_SUBTREE(tree, parent, "ofp_table_feature_prop", length + OFP_MATCH_OXM_PADDING(length));
    ADD_CHILD(tree, "ofp_table_feature_prop.type", 2);
    ADD_CHILD(tree, "ofp_table_feature_prop.length", 2);

    if (type == OFPTFPT_INSTRUCTIONS || type == OFPTFPT_INSTRUCTIONS_MISS) {
        guint32 end = this->_offset - sizeof(struct ofp_table_feature_prop_instructions) + length;
        while (this->_offset < end)
            this->dissect_ofp_instruction(tree);
    }
    else if (type == OFPTFPT_NEXT_TABLES || type == OFPTFPT_NEXT_TABLES_MISS) {
        guint32 end = this->_offset - sizeof(struct ofp_table_feature_prop_next_tables) + length;
        while (this->_offset < end) {
            ADD_CHILD(tree, "ofp_table_feature_prop_next_tables.next_table_ids", 1);
        }
    }
    else if (type == OFPTFPT_WRITE_ACTIONS ||
             type == OFPTFPT_WRITE_ACTIONS_MISS ||
             type == OFPTFPT_APPLY_ACTIONS ||
             type == OFPTFPT_APPLY_ACTIONS_MISS) {
        guint32 end = this->_offset - sizeof(struct ofp_table_feature_prop_actions) + length;
        while (this->_offset < end)
            this->dissect_ofp_action(tree);
    }
    else if (type == OFPTFPT_MATCH ||
             type == OFPTFPT_WILDCARDS ||
             type == OFPTFPT_WRITE_SETFIELD ||
             type == OFPTFPT_WRITE_SETFIELD_MISS ||
             type == OFPTFPT_APPLY_SETFIELD ||
             type == OFPTFPT_APPLY_SETFIELD_MISS) {
        guint32 end = this->_offset - sizeof(struct ofp_table_feature_prop_oxm) + length;
        while (this->_offset < end) {
            ADD_SUBTREE(oxmtree, tree, "ofp_oxm", 4);
            this->dissect_ofp_oxm_header(oxmtree);
        }
    }
    else { // If we don't know what to do, discard
        CONSUME_BYTES(length);
    }

    ADD_CHILD(tree, "padding", OFP_MATCH_OXM_PADDING(length));
}

void DissectorContext::dissect_ofp_table_features(proto_tree* parent) {
    READ_UINT16(length);
    ADD_SUBTREE(tree, parent, "ofp_table_features", length);
    ADD_CHILD(tree, "ofp_table_features.length", 2);
    ADD_CHILD(tree, "ofp_table_features.table_id", 1);
    ADD_CHILD(tree, "padding", 5);
    ADD_CHILD(tree, "ofp_table_features.name", OFP_MAX_TABLE_NAME_LEN);
    ADD_CHILD(tree, "ofp_table_features.metadata_match", 8);
    ADD_CHILD(tree, "ofp_table_features.metadata_write", 8);
    ADD_CHILD(tree, "ofp_table_features.config", 4); // TODO: flags
    ADD_CHILD(tree, "ofp_table_features.max_entries", 4);

    guint32 end = this->_offset - sizeof(struct ofp_table_features) + length;
    while (this->_offset < end) {
        dissect_ofp_table_feature_prop(tree);
    }
}

void DissectorContext::dissect_ofp_flow_stats_request(proto_tree* parent) {
    ADD_SUBTREE(tree, parent, "ofp_flow_stats_request", sizeof(struct ofp_flow_stats_request));
    ADD_CHILD(tree, "ofp_flow_stats_request.table_id", 1);
    ADD_CHILD(tree, "padding", 3);
    ADD_CHILD(tree, "ofp_flow_stats_request.out_port", 4);
    ADD_CHILD(tree, "ofp_flow_stats_request.out_group", 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_flow_stats_request.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_stats_request.cookie_mask", 8);

    this->dissect_ofp_match(tree);
}

void DissectorContext::dissect_ofp_flow_stats(proto_tree* parent) {
    READ_UINT16(length);
    guint32 end = this->_offset + length;

    ADD_TREE(tree, "ofp_flow_stats");
    ADD_CHILD(tree, "ofp_flow_stats.length", 2);
    ADD_CHILD(tree, "ofp_flow_stats.table_id", 1);
    ADD_CHILD(tree, "padding", 1);
    ADD_CHILD(tree, "ofp_flow_stats.duration_sec", 4);
    ADD_CHILD(tree, "ofp_flow_stats.duration_nsec", 4);
    ADD_CHILD(tree, "ofp_flow_stats.priority", 2);
    ADD_CHILD(tree, "ofp_flow_stats.idle_timeout", 2);
    ADD_CHILD(tree, "ofp_flow_stats.hard_timeout", 2);
    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_flow_stats.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.RESERVED", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_RESET_COUNTS", 2, flags);
    CONSUME_BYTES(2);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_flow_stats.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_stats.packet_count", 8);
    ADD_CHILD(tree, "ofp_flow_stats.byte_count", 8);
    this->dissect_ofp_match(tree);

    while (this->_offset < end) {
        this->dissect_ofp_instruction(tree);
    }
}

void DissectorContext::dissect_ofp_multipart_request() {
    ADD_TREE(tree, "ofp_multipart_request");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_multipart_request.type", 2);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_multipart_request.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_multipart_request_flags.OFPMPF_REQ_MORE", 2, flags);
    CONSUME_BYTES(2);

    ADD_CHILD(tree, "padding", 4);

    switch (type) {
        case OFPMP_FLOW:
            this->dissect_ofp_flow_stats_request(tree);
            break;
        case OFPMP_TABLE_FEATURES:
            while ((this->_oflen - this->_offset) > 0) {
                this->dissect_ofp_table_features(tree);
            }
            break;
        default:
            ADD_CHILD(tree, "ofp_multipart_reply.body", this->_oflen - this->_offset);
            break;
    }
}

void DissectorContext::dissect_ofp_multipart_reply() {
    ADD_TREE(tree, "ofp_multipart_reply");

    READ_UINT16(type);
    ADD_CHILD(tree, "ofp_multipart_reply.type", 2);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_multipart_reply.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_multipart_reply_flags.OFPMPF_REPLY_MORE", 2, flags);
    CONSUME_BYTES(2);

    ADD_CHILD(tree, "padding", 4);

    switch (type) {
        case OFPMP_FLOW:
            while ((this->_oflen - this->_offset) > 0) {
                this->dissect_ofp_flow_stats(tree);
            }
            break;
        case OFPMP_TABLE_FEATURES:
            while ((this->_oflen - this->_offset) > 0) {
                this->dissect_ofp_table_features(tree);
            }
            break;
        default:
            ADD_CHILD(tree, "ofp_multipart_reply.body", this->_oflen - this->_offset);
            break;
    }
}

void DissectorContext::dissect_ofp_portStatus() {
    ADD_TREE(tree, "pstatus");

    ADD_CHILD(tree, "pstatus.reason", 1);
    ADD_CHILD(tree, "padding", 7);

    ADD_TREE(desc_tree, "pdesc");
    this->dissect_ofp_port(desc_tree);
}

void DissectorContext::dissect_ofp_flow_mod() {
    ADD_TREE(tree, "ofp_flow_mod");

    ADD_CHILD(tree, "ofp_flow_mod.cookie", 8);
    ADD_CHILD(tree, "ofp_flow_mod.cookie_mask", 8);
    ADD_CHILD(tree, "ofp_flow_mod.table_id", 1);
    ADD_CHILD(tree, "ofp_flow_mod.command", 1);
    ADD_CHILD(tree, "ofp_flow_mod.idle_timeout", 2);
    ADD_CHILD(tree, "ofp_flow_mod.hard_timeout", 2);
    ADD_CHILD(tree, "ofp_flow_mod.priority", 2);
    ADD_CHILD(tree, "ofp_flow_mod.buffer_id", 4);
    ADD_CHILD(tree, "ofp_flow_mod.out_port", 4);
    ADD_CHILD(tree, "ofp_flow_mod.out_group", 4);

    READ_UINT16(flags);
    ADD_SUBTREE(flags_tree, tree, "ofp_flow_mod.flags", 2);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.RESERVED", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", 2, flags);
    ADD_BOOLEAN(flags_tree, "ofp_flow_mod_flags.OFPFF_RESET_COUNTS", 2, flags);
    CONSUME_BYTES(2);
    ADD_CHILD(tree, "padding", 2);

    this->dissect_ofp_match(tree);

    try {
        while ((this->_oflen - this->_offset) > 0) {
            this->dissect_ofp_instruction(tree);
        }
    }
    catch (const ZeroLenInstruction &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_packet_in() {
    ADD_TREE(tree, "ofp_packet_in");

    ADD_CHILD(tree, "ofp_packet_in.buffer_id", 4);
    ADD_CHILD(tree, "ofp_packet_in.total_len", 2);
    ADD_CHILD(tree, "ofp_packet_in.reason", 1);
    ADD_CHILD(tree, "ofp_packet_in.table_id", 1);
    ADD_CHILD(tree, "ofp_packet_in.cookie", 8);

    this->dissect_ofp_match(tree);

    ADD_CHILD(tree, "padding", 2);

    if (this->_oflen - this->_offset > 0) {
	ADD_DISSECTOR(tree, "ofp_packet_in.data", this->_oflen - this->_offset);
    } else
	ADD_CHILD(tree, "ofp_packet_in.data", this->_oflen - this->_offset);
}

void DissectorContext::dissect_ofp_packet_out() {
    ADD_TREE(tree, "ofp_packet_out");

    ADD_CHILD(tree, "ofp_packet_out.buffer_id", 4);
    ADD_CHILD(tree, "ofp_packet_out.in_port", 4);
    READ_UINT16(actions_len);
    ADD_CHILD(tree, "ofp_packet_out.actions_len", 2);
    ADD_CHILD(tree, "padding", 6);

    int end = this->_offset + actions_len;
    while (this->_offset < end) {
        dissect_ofp_action(tree);
    }

    // TODO: should we check to see it it's really Ethernet?
    if (this->_oflen - this->_offset > 0) {
	   ADD_DISSECTOR(tree, "ofp_packet_out.data", this->_oflen - this->_offset);
    }
    else {
	   ADD_CHILD(tree, "ofp_packet_out.data", this->_oflen - this->_offset);
    }
}

void DissectorContext::dissectGroupMod() {
    ADD_TREE(tree, "groupmod");

    ADD_CHILD(tree, "groupmod.command", 2);
    ADD_CHILD(tree, "groupmod.type", 1);
    ADD_CHILD(tree, "padding", 1);
    ADD_CHILD(tree, "groupmod.groupid", 4);

    try {
        while((this->_oflen - this->_offset) > 0) {
            this->dissectGroupBucket(tree);
        }
    }
    catch (const ZeroLenBucket &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_port_mod() {
    ADD_TREE(tree, "ofp_port_mod");

    ADD_CHILD(tree, "ofp_port_mod.num", 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_port_mod.hwaddr", 6);
    ADD_CHILD(tree, "padding", 2);

    READ_UINT32(ofppc);
    ADD_SUBTREE(config_tree, tree, "ofp_port_mod.config", 4);
    ADD_BOOLEAN(config_tree, "ofp_port_mod_config.RESERVED", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_mod_config.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_mod_config.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_mod_config.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_mod_config.OFPPC_NO_PACKET_IN", 4, ofppc);
    CONSUME_BYTES(4);

    READ_UINT32(mask);
    ADD_SUBTREE(mask_tree, tree, "ofp_port_mod.mask", 4);
    ADD_BOOLEAN(mask_tree, "ofp_port_mod_mask.RESERVED", 4, ofppc);
    ADD_BOOLEAN(mask_tree, "ofp_port_mod_mask.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(mask_tree, "ofp_port_mod_mask.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(mask_tree, "ofp_port_mod_mask.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(mask_tree, "ofp_port_mod_mask.OFPPC_NO_PACKET_IN", 4, ofppc);
    CONSUME_BYTES(4);

    ADD_SUBTREE(advertise_tree, tree, "ofp_port_mod.advertise", 4);
    dissectOFPPF(advertise_tree);

    ADD_CHILD(tree, "padding", 4);
}

void DissectorContext::dissect_ofp_table_mod() {
    ADD_TREE(tree, "ofp_table_mod");

    ADD_CHILD(tree, "ofp_table_mod.id", 1);
    ADD_CHILD(tree, "padding", 3);

    READ_UINT32(config);
    ADD_SUBTREE(config_tree, tree, "ofp_table_mod.config", 4);
    ADD_BOOLEAN(config_tree, "ofp_table_config.RESERVED", 4, config);
    CONSUME_BYTES(4);
}

void DissectorContext::dissect_ofp_port(proto_tree* parent) {
    ADD_SUBTREE(tree, parent, "ofp_port", 64);

    ADD_CHILD(tree, "ofp_port.num", 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_port.hwaddr", 6);
    ADD_CHILD(tree, "padding", 2);
    ADD_CHILD(tree, "ofp_port.name", 16);

    ADD_SUBTREE(config_tree, tree, "ofp_port.config", 4);
    READ_UINT32(ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.RESERVED", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_PORT_DOWN", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_RECV", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_FWD", 4, ofppc);
    ADD_BOOLEAN(config_tree, "ofp_port_config.OFPPC_NO_PACKET_IN", 4, ofppc);
    CONSUME_BYTES(4);

    ADD_SUBTREE(state_tree, tree, "ofp_port.state", 4);
    READ_UINT32(ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.RESERVED", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_LINK_DOWN", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_BLOCKED", 4, ofpps);
    ADD_BOOLEAN(state_tree, "ofp_port_state.OFPPS_LIVE", 4, ofpps);
    CONSUME_BYTES(4);

    ADD_SUBTREE(curr_feats_tree, tree, "ofp_port.curr_feats", 4);
    dissectOFPPF(curr_feats_tree);

    ADD_SUBTREE(advertised_tree, tree, "ofp_port.advertised", 4);
    dissectOFPPF(advertised_tree);

    ADD_SUBTREE(supported_tree, tree, "ofp_port.supported", 4);
    dissectOFPPF(supported_tree);

    ADD_SUBTREE(peer_tree, tree, "ofp_port.peer", 4);
    dissectOFPPF(peer_tree);

    ADD_CHILD(tree, "ofp_port.curr_speed", 4);
    ADD_CHILD(tree, "ofp_port.max_speed", 4);
}

void DissectorContext::dissectOFPPF (proto_tree *tree) {
    READ_UINT32(ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.RESERVED", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10MB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10MB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100MB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100MB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1GB_HD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_10GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_40GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_100GB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_1TB_FD", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_OTHER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_COPPER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_FIBER", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_AUTONEG", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_PAUSE", 4, ofppf);
    ADD_BOOLEAN(tree, "ofp_port_features.OFPPF_PAUSE_ASYM", 4, ofppf);
    CONSUME_BYTES(4);
}

void DissectorContext::dissect_ofp_match(proto_tree *parent) {
    /*FIXME: We should care if the type isn't OXM (0x01) */

    this->_offset += 2; // read ahead
    READ_UINT16(length);
    this->_offset -= 2;

    ADD_SUBTREE(tree, parent, "ofp_match", length);

    ADD_CHILD(tree, "ofp_match.type", 2);
    ADD_CHILD(tree, "ofp_match.len", 2);

    /* If the length is 4, we have an empty ofp_match, meaning that oxm_fields
    is filled with padding bits. Otherwise, we have valid OXM fields. */
    if (length == 4) {
        ADD_CHILD(tree, "padding", 4);
    }
    else {
        guint32 to_consume = length - 4;
        guint32 consumed = 0;
        while (consumed < to_consume) {
            consumed += dissect_ofp_oxm_field(tree);
        }
        if (consumed > to_consume)
            SHOW_ERROR(tree, "Match length smaller than OXM fields");

        ADD_CHILD(tree, "padding", OFP_MATCH_OXM_PADDING(length));
    }
}

void DissectorContext::dissect_ofp_oxm_header(proto_tree *tree) {
    ADD_CHILD(tree, "ofp_oxm.oxm_class", 2);
    ADD_CHILD(tree, "ofp_oxm.oxm_field", 1);
    this->_offset -= 1; // Go back, we're not done with this byte!
    ADD_CHILD(tree, "ofp_oxm.oxm_hasmask", 1);
    ADD_CHILD(tree, "ofp_oxm.oxm_length", 1);
}


int DissectorContext::dissect_ofp_oxm_field(proto_tree *parent) {
    // Header contains length
    READ_UINT32(header);
    // Length tells us how long this field is
    guint32 length = UNPACK_OXM_LENGTH(header);

    ADD_SUBTREE(tree, parent, "ofp_oxm", length + 4);
    dissect_ofp_oxm_header(tree);

    // Choose field type to display the formatted value
    // TODO: add support for more types
    std::string value_field;
    switch (UNPACK_OXM_FIELD(header)) {
        case OFPXMT_OFB_IPV4_SRC:
        case OFPXMT_OFB_IPV4_DST:
            value_field = "ofp_oxm.value-IPV4";
            break;
        default:
            value_field = "ofp_oxm.value";
            break;
    }

    // If we have a mask, the body is double its normal size
    if (UNPACK_OXM_HASMASK(header)) {
        ADD_CHILD(tree, value_field, length/2);
        ADD_CHILD(tree, "ofp_oxm.mask", length/2);
    }
    else {
        ADD_CHILD(tree, value_field, length);
    }

    return length + 4;
}


void DissectorContext::dissect_ofp_instruction(proto_tree* parent) {
    READ_UINT16(type);
    this->_offset += 2; // read ahead
    READ_UINT16(len);
    this->_offset -= 2;

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_instruction", len);
    ADD_CHILD(tree, "ofp_instruction.type", 2);
    ADD_CHILD(tree, "ofp_instruction.len", 2);

    // If we have just a header, stop here
    if (len <= 4)
        return;

    switch (type) {
        case OFPIT_GOTO_TABLE:
            ADD_CHILD(tree, "ofp_instruction_goto_table.table_id", 1);
            ADD_CHILD(tree, "padding", 3);
            break;
        case OFPIT_WRITE_METADATA:
            ADD_CHILD(tree, "padding", 4);
            ADD_CHILD(tree, "ofp_instruction_write_metadata.metadata", 8);
            ADD_CHILD(tree, "ofp_instruction_write_metadata.metadata_mask", 8);
            break;
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS:
            ADD_CHILD(tree, "padding", 4);
            try {
                while (this->_offset < message_end)
                    this->dissect_ofp_action(tree);
            }
            catch (const ZeroLenAction &e) {
                break;
            }
            break;
        case OFPIT_CLEAR_ACTIONS:
            ADD_CHILD(tree, "padding", 4);
            break;
        case OFPIT_METER:
            ADD_CHILD(tree, "ofp_instruction_meter.meter_id", 4);
            break;

        default:
            // Unknown type
            CONSUME_BYTES(message_end - this->_offset);
    }
}

void DissectorContext::dissect_ofp_action(proto_tree* parent) {
    READ_UINT16(type);
    this->_offset += 2; // read ahead
    READ_UINT16(len);
    this->_offset -= 2;

    guint32 oxm_len;

//    if (len == 0)
//      { throw ZeroLenAction(); }

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_action", len);
    ADD_CHILD(tree, "ofp_action.type", 2);
    ADD_CHILD(tree, "ofp_action.len", 2);

    // If we have just a header, stop here
    if (len <= 4)
        return;

    switch (type) {
        case OFPAT_OUTPUT:
            ADD_CHILD(tree, "ofp_action_output.port", 4);
            ADD_CHILD(tree, "ofp_action_output.max_len", 2);
            ADD_CHILD(tree, "padding", 6);
            break;
        // Fieldless actions
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN:
        case OFPAT_DEC_NW_TTL:
        case OFPAT_DEC_MPLS_TTL:
        case OFPAT_POP_VLAN:
        case OFPAT_POP_PBB:
            ADD_CHILD(tree, "padding", 4);
            break;
        case OFPAT_SET_MPLS_TTL:
            ADD_CHILD(tree, "ofp_action_mpls_ttl.mpls_ttl", 1);
            ADD_CHILD(tree, "padding", 3);
            break;
        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_MPLS:
        case OFPAT_PUSH_PBB:
            ADD_CHILD(tree, "ofp_action_push.ethertype", 2);
            ADD_CHILD(tree, "padding", 2);
            break;
        case OFPAT_POP_MPLS:
            ADD_CHILD(tree, "ofp_action_pop_mpls.ethertype", 2);
            ADD_CHILD(tree, "padding", 2);
            break;
        case OFPAT_SET_QUEUE:
            ADD_CHILD(tree, "ofp_action_set_queue.queue_id", 4);
            break;
        case OFPAT_GROUP:
            ADD_CHILD(tree, "ofp_action_group.group_id", 4);
            break;
        case OFPAT_SET_NW_TTL:
            ADD_CHILD(tree, "ofp_action_nw_ttl.nw_ttl", 1);
            ADD_CHILD(tree, "padding", 3);
            break;
        case OFPAT_SET_FIELD:
            // We can reuse ofp_oxm_field becauseofp_action_set_field contains only one OXM field
            oxm_len = dissect_ofp_oxm_field(tree);
            ADD_CHILD(tree, "padding", OFP_ACTION_SET_FIELD_OXM_PADDING(oxm_len));
            break;
        case OFPAT_EXPERIMENTER:
            ADD_CHILD(tree, "ofp_action_experimenter_header.experimenter", 4);
            break;
        default:
            CONSUME_BYTES(message_end - this->_offset);
            break;
    }
}

void DissectorContext::dissectGroupBucket(proto_tree* parent) {
    READ_UINT16(len);

    if (len == 0)
        throw ZeroLenBucket();

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "groupmod.bucket", len);
    ADD_CHILD(tree, "groupmod.bucket.len", 2);
    ADD_CHILD(tree, "groupmod.bucket.weight", 2);
    ADD_CHILD(tree, "groupmod.bucket.watch_port", 4);
    ADD_CHILD(tree, "groupmod.bucket.watch_group", 4);
    ADD_CHILD(tree, "padding", 4);

    try {
        while (this->_offset < message_end) {
            this->dissect_ofp_action(tree);
        }
    }
    catch(const ZeroLenAction &e) {
        return;
    }
}

void DissectorContext::dissect_ofp_role_request() {
    ADD_TREE(tree, "ofp_role_request");
    ADD_CHILD(tree, "ofp_role_request.role", 4);
    ADD_CHILD(tree, "padding", 4);
    ADD_CHILD(tree, "ofp_role_request.generation_id", 8);
}

void DissectorContext::dissect_ofp_get_async_reply() {
    ADD_TREE(tree, "ofp_async_config");

    READ_UINT32(packet_in_eq_ms);
    ADD_SUBTREE(packet_in_eq_ms_tree, tree, "ofp_async_config.packet_in_mask-eq_ms", 4);
    ADD_BOOLEAN(packet_in_eq_ms_tree, "ofp_packet_in_reason_bitmask.OFPR_NO_MATCH", 4, packet_in_eq_ms);
    ADD_BOOLEAN(packet_in_eq_ms_tree, "ofp_packet_in_reason_bitmask.OFPR_ACTION", 4, packet_in_eq_ms);
    ADD_BOOLEAN(packet_in_eq_ms_tree, "ofp_packet_in_reason_bitmask.OFPR_INVALID_TTL", 4, packet_in_eq_ms);
    ADD_BOOLEAN(packet_in_eq_ms_tree, "ofp_packet_in_reason_bitmask.RESERVED", 4, packet_in_eq_ms);
    CONSUME_BYTES(4);

    READ_UINT32(packet_in_sl);
    ADD_SUBTREE(packet_in_sl_tree, tree, "ofp_async_config.packet_in_mask-sl", 4);
    ADD_BOOLEAN(packet_in_sl_tree, "ofp_packet_in_reason_bitmask.OFPR_NO_MATCH", 4, packet_in_sl);
    ADD_BOOLEAN(packet_in_sl_tree, "ofp_packet_in_reason_bitmask.OFPR_ACTION", 4, packet_in_sl);
    ADD_BOOLEAN(packet_in_sl_tree, "ofp_packet_in_reason_bitmask.OFPR_INVALID_TTL", 4, packet_in_sl);
    ADD_BOOLEAN(packet_in_sl_tree, "ofp_packet_in_reason_bitmask.RESERVED", 4, packet_in_sl);
    CONSUME_BYTES(4);

    READ_UINT32(port_status_eq_ms);
    ADD_SUBTREE(port_status_eq_ms_tree, tree, "ofp_async_config.port_status_mask-eq_ms", 4);
    ADD_BOOLEAN(port_status_eq_ms_tree, "ofp_port_reason_bitmask.OFPPR_ADD", 4, port_status_eq_ms);
    ADD_BOOLEAN(port_status_eq_ms_tree, "ofp_port_reason_bitmask.OFPPR_DELETE", 4, port_status_eq_ms);
    ADD_BOOLEAN(port_status_eq_ms_tree, "ofp_port_reason_bitmask.OFPPR_MODIFY", 4, port_status_eq_ms);
    ADD_BOOLEAN(port_status_eq_ms_tree, "ofp_port_reason_bitmask.RESERVED", 4, port_status_eq_ms);
    CONSUME_BYTES(4);

    READ_UINT32(port_status_sl);
    ADD_SUBTREE(port_status_sl_tree, tree, "ofp_async_config.port_status_mask-sl", 4);
    ADD_BOOLEAN(port_status_sl_tree, "ofp_port_reason_bitmask.OFPPR_ADD", 4, port_status_sl);
    ADD_BOOLEAN(port_status_sl_tree, "ofp_port_reason_bitmask.OFPPR_DELETE", 4, port_status_sl);
    ADD_BOOLEAN(port_status_sl_tree, "ofp_port_reason_bitmask.OFPPR_MODIFY", 4, port_status_sl);
    ADD_BOOLEAN(port_status_sl_tree, "ofp_port_reason_bitmask.RESERVED", 4, port_status_sl);
    CONSUME_BYTES(4);

    READ_UINT32(flow_removed_eq_ms);
    ADD_SUBTREE(flow_removed_eq_ms_tree, tree, "ofp_async_config.flow_removed_mask-eq_ms", 4);
    ADD_BOOLEAN(flow_removed_eq_ms_tree, "ofp_flow_removed_reason_bitmask.OFPRR_IDLE_TIMEOUT", 4, flow_removed_eq_ms);
    ADD_BOOLEAN(flow_removed_eq_ms_tree, "ofp_flow_removed_reason_bitmask.OFPRR_HARD_TIMEOUT", 4, flow_removed_eq_ms);
    ADD_BOOLEAN(flow_removed_eq_ms_tree, "ofp_flow_removed_reason_bitmask.OFPRR_DELETE", 4, flow_removed_eq_ms);
    ADD_BOOLEAN(flow_removed_eq_ms_tree, "ofp_flow_removed_reason_bitmask.OFPRR_GROUP_DELETE", 4, flow_removed_eq_ms);
    ADD_BOOLEAN(flow_removed_eq_ms_tree, "ofp_flow_removed_reason_bitmask.RESERVED", 4, flow_removed_eq_ms);
    CONSUME_BYTES(4);

    READ_UINT32(flow_removed_sl);
    ADD_SUBTREE(flow_removed_sl_tree, tree, "ofp_async_config.flow_removed_mask-sl", 4);
    ADD_BOOLEAN(flow_removed_sl_tree, "ofp_flow_removed_reason_bitmask.OFPRR_IDLE_TIMEOUT", 4, flow_removed_sl);
    ADD_BOOLEAN(flow_removed_sl_tree, "ofp_flow_removed_reason_bitmask.OFPRR_HARD_TIMEOUT", 4, flow_removed_sl);
    ADD_BOOLEAN(flow_removed_sl_tree, "ofp_flow_removed_reason_bitmask.OFPRR_DELETE", 4, flow_removed_sl);
    ADD_BOOLEAN(flow_removed_sl_tree, "ofp_flow_removed_reason_bitmask.OFPRR_GROUP_DELETE", 4, flow_removed_sl);
    ADD_BOOLEAN(flow_removed_sl_tree, "ofp_flow_removed_reason_bitmask.RESERVED", 4, flow_removed_sl);
    CONSUME_BYTES(4);
}

void DissectorContext::dissect_ofp_meter_mod() {
    ADD_TREE(tree, "ofp_meter_mod");

    ADD_CHILD(tree, "ofp_meter_mod.command", 2);
    // Only one flag is supported by the spec for now
    ADD_CHILD(tree, "ofp_meter_mod.flags", 2);
    ADD_CHILD(tree, "ofp_meter_mod.meter_id", 4);

    while (this->_offset < this->_oflen) {
        this->dissect_ofp_meter_band(tree);
    }
}

void DissectorContext::dissect_ofp_meter_band(proto_tree* parent) {
    READ_UINT16(type);
    this->_offset += 2; // read ahead
    READ_UINT16(len);
    this->_offset -= 2; // go back to the start

    guint32 message_end = this->_offset + len;

    ADD_SUBTREE(tree, parent, "ofp_meter_band", len);
    ADD_CHILD(tree, "ofp_meter_band.type", 2);
    ADD_CHILD(tree, "ofp_meter_band.len", 2);
    ADD_CHILD(tree, "ofp_meter_band.rate", 4);
    ADD_CHILD(tree, "ofp_meter_band.burst_size", 4);

    switch (type) {
        case OFPMBT_DROP:
            ADD_CHILD(tree, "padding", 4);
            break;
        case OFPMBT_DSCP_REMARK:
            ADD_CHILD(tree, "ofp_meter_band_dscp_remark.prec_level", 1);
            ADD_CHILD(tree, "padding", 3);
            break;
        case OFPMBT_EXPERIMENTER:
            ADD_CHILD(tree, "ofp_meter_band_experimenter.experimenter", 4);
            break;
        default:
            CONSUME_BYTES(message_end - this->_offset);
            break;
    }
}

void DissectorContext::setupFields() {
    TREE_FIELD("data", "Openflow Protocol");
    FIELD("padding", "Padding", FT_NONE, BASE_NONE, NO_VALUES, NO_MASK);

    // Header
    TREE_FIELD("ofp_header", "Header");
    FIELD("ofp_header.version", "Version", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_header.type", "Type", FT_UINT8, BASE_DEC, VALUES(ofp_type), NO_MASK);
    FIELD("ofp_header.length", "Length", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_header.xid", "Transaction ID", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    // Echo Request/Reply
    FIELD("echo", "Echo Data", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);

    // ofp_error
    TREE_FIELD("ofp_error", "Error");
    FIELD("ofp_error.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_error_type), NO_MASK);
    FIELD("ofp_error.code.OFPET_HELLO_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_hello_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_REQUEST", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_request_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_ACTION", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_action_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_INSTRUCTION", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_instruction_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_BAD_MATCH", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_bad_match_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_FLOW_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_flow_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_GROUP_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_group_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_PORT_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_port_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_TABLE_MOD_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_table_mod_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_QUEUE_OP_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_queue_op_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_SWITCH_CONFIG_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_switch_config_failed_code), NO_MASK);
    FIELD("ofp_error.code.OFPET_ROLE_REQUEST_FAILED", "Code", FT_UINT16, BASE_HEX, VALUES(ofp_role_request_failed_code), NO_MASK);
    FIELD("ofp_error.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    // Feature Request
    FIELD("featreq", "Feature Request", FT_NONE, BASE_NONE, NO_VALUES, NO_MASK);

    // ofp_switch_features
    TREE_FIELD("ofp_switch_features", "Feature Reply");
    FIELD("ofp_switch_features.datapath_id", "Datapath ID", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_switch_features.n_buffers", "Buffers", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_switch_features.n_tables", "Tables", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_switch_features.auxiliary_id", "Auxiliary ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_switch_features.capabilities", "Capabilities", FT_UINT32);
    FIELD("ofp_switch_features.reserved", "Reserved", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    TREE_FIELD("ofp_switch_features.ports", "Ports");

    // Port
    TREE_FIELD("ofp_port", "Port Description");
    FIELD("ofp_port.num", "Number", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port.hwaddr", "Hardware Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_port.name", "Name", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port.config", "Config", FT_UINT32);
    BITMAP_FIELD("ofp_port.state", "State", FT_UINT32);
    BITMAP_FIELD("ofp_port.curr_feats", "Current Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.advertised", "Advertised Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.supported", "Supported Features", FT_UINT32);
    BITMAP_FIELD("ofp_port.peer", "Peer Features", FT_UINT32);
    FIELD("ofp_port.curr_speed", "Current Speed (kbps)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port.max_speed", "Maximum Speed (kbps)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    // Switch Config Reply
    TREE_FIELD("ofp_switch_config", "Switch Configuration");
    BITMAP_FIELD("ofp_switch_config.flags", "Flags", FT_UINT16);
    FIELD("ofp_switch_config.miss_send_len", "Max new flow bytes to controller", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    // Flow Match
    TREE_FIELD("ofp_match", "Match");
    FIELD("ofp_match.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_match_type), NO_MASK);
    FIELD("ofp_match.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    // ofp_oxm_field
    TREE_FIELD("ofp_oxm", "OXM field");
    FIELD("ofp_oxm.oxm_class", "Class", FT_UINT16, BASE_HEX, VALUES(ofp_oxm_class), NO_MASK);
    FIELD("ofp_oxm.oxm_field", "Field", FT_UINT8, BASE_HEX, VALUES(oxm_ofb_match_fields), 0xFE);
    FIELD("ofp_oxm.oxm_hasmask", "Has mask", FT_BOOLEAN, 1, TFS(&tfs_yes_no), 0x01);
    FIELD("ofp_oxm.oxm_length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_oxm.value", "Value", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_oxm.value-IPV4", "Value", FT_IPv4, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_oxm.mask", "Mask", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    // ofp_action_*
    TREE_FIELD("ofp_action", "Action");
    FIELD("ofp_action.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_action_type), NO_MASK);
    FIELD("ofp_action.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.port", "Port", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_output.max_len", "Max Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_group.group_id", "Group ID", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_set_queue.queue_id", "Queue ID", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_mpls_ttl.mpls_ttl", "MPLS TTL", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_nw_ttl.nw_ttl", "NW TTL", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_action_push.ethertype", "Ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_action_pop_mpls.ethertype", "Ethertype", FT_UINT16, BASE_HEX, NO_VALUES, NO_MASK);
    // ofp_action_set_field is defined using ofp_oxm
    FIELD("ofp_action_experimenter_header.experimenter", "Experimenter ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);

    // ofp_multipart_request
    TREE_FIELD("ofp_multipart_request", "Multipart request");
    FIELD("ofp_multipart_request.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_multipart_types), NO_MASK);
    BITMAP_FIELD("ofp_multipart_request.flags", "Flags", FT_UINT16);
    FIELD("ofp_multipart_request.body", "Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    // ofp_multipart_reply
    TREE_FIELD("ofp_multipart_reply", "Multipart reply");
    FIELD("ofp_multipart_reply.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_multipart_types), NO_MASK);
    BITMAP_FIELD("ofp_multipart_reply.flags", "Flags", FT_UINT16);
    FIELD("ofp_multipart_reply.body", "Body", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    // ofp_flow_stats_request
    TREE_FIELD("ofp_flow_stats_request", "Individual flow statistics request");
    FIELD("ofp_flow_stats_request.table_id", "Table ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.out_port", "Output Port", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.out_group", "Output Group", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats_request.cookie_mask", "Cookie mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    // ofp_flow_stats
    TREE_FIELD("ofp_flow_stats", "Individual Flow Stats");
    FIELD("ofp_flow_stats.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.table_id", "Table ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.duration_sec", "Duration (sec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.duration_nsec", "Duration (nsec)", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.priority", "Priority", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.idle_timeout", "Idle Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.hard_timeout", "Hard Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_flow_stats.flags", "Flags", FT_UINT16);
    FIELD("ofp_flow_stats.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.packet_count", "Packet count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_stats.byte_count", "Byte count", FT_UINT64, BASE_DEC, NO_VALUES, NO_MASK);

    // ofp_table_features
    TREE_FIELD("ofp_table_features", "Table features");
    FIELD("ofp_table_features.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_features.table_id", "Table ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_features.name", "Name", FT_STRING, BASE_NONE, NO_VALUES, NO_MASK);
    FIELD("ofp_table_features.metadata_match", "Metadata match", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_table_features.metadata_write", "Metadata write", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_table_features.config", "Config", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_table_features.max_entries", "Max entries", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    // ofp_table_feature_prop
    TREE_FIELD("ofp_table_feature_prop", "Property");
    FIELD("ofp_table_feature_prop.type", "Type", FT_UINT16, BASE_DEC, VALUES(ofp_table_feature_prop_type), NO_MASK);
    FIELD("ofp_table_feature_prop.length", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_table_feature_prop_next_tables.next_table_ids", "Next table ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);

    // Port Status
    TREE_FIELD("pstatus", "Port Status");
    FIELD("pstatus.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_port_reason), NO_MASK);
    TREE_FIELD("pdesc", "Port Description");

    // ofp_flow_mod
    TREE_FIELD("ofp_flow_mod", "Flow Mod");
    FIELD("ofp_flow_mod.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.cookie_mask", "Cookie Mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.table_id", "Table ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.command", "Command", FT_UINT8, BASE_HEX, VALUES(ofp_flow_mod_command), NO_MASK);
    FIELD("ofp_flow_mod.idle_timeout", "Idle Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.hard_timeout", "Hard Timeout", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.priority", "Priority", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.out_port", "Output Port", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_flow_mod.out_group", "Output Group", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_flow_mod.flags", "Flags", FT_UINT16);

    // ofp_instruction
    TREE_FIELD("ofp_instruction", "Instruction");
    FIELD("ofp_instruction.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_instruction_type), NO_MASK);
    FIELD("ofp_instruction.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);

    FIELD("ofp_instruction_goto_table.table_id", "Table ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_write_metadata.metadata", "Metadata", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_write_metadata.metadata_mask", "Metadata Mask", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_instruction_meter.meter_id", "Meter ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);

    // Group Mod
    TREE_FIELD("groupmod", "Group Mod");
    FIELD("groupmod.command", "Command", FT_UINT16, BASE_HEX, VALUES(ofp_group_mod_command), NO_MASK);
    FIELD("groupmod.type", "Type", FT_UINT8, BASE_HEX, VALUES(ofp_group_type), NO_MASK);
    FIELD("groupmod.groupid", "Group ID", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    TREE_FIELD("groupmod.bucket", "Bucket");
    FIELD("groupmod.bucket.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("groupmod.bucket.weight", "Weight", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("groupmod.bucket.watch_port", "Watch Port", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("groupmod.bucket.watch_group", "Watch Group", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);

    // ofp_port_mod
    TREE_FIELD("ofp_port_mod", "Port Mod");
    FIELD("ofp_port_mod.num", "Number", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_port_mod.hwaddr", "Hardware Address", FT_ETHER, BASE_NONE, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_port_mod.config", "Config", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.mask", "Mask", FT_UINT32);
    BITMAP_FIELD("ofp_port_mod.advertise", "Advertise", FT_UINT32);

    // ofp_table_mod
    TREE_FIELD("ofp_table_mod", "Table Mod");
    FIELD("ofp_table_mod.id", "ID", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    BITMAP_FIELD("ofp_table_mod.config", "Config", FT_UINT32);

    // ofp_packet_in
    TREE_FIELD("ofp_packet_in", "Packet in");
    FIELD("ofp_packet_in.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.total_len", "Total length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.reason", "Reason", FT_UINT8, BASE_HEX, VALUES(ofp_packet_in_reason), NO_MASK);
    FIELD("ofp_packet_in.table_id", "Table ID", FT_UINT8, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.cookie", "Cookie", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_in.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    // ofp_packet_out
    TREE_FIELD("ofp_packet_out", "Packet out");
    FIELD("ofp_packet_out.buffer_id", "Buffer ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.in_port", "Input port", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.actions_len", "Actions length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_packet_out.data", "Data", FT_BYTES, BASE_NONE, NO_VALUES, NO_MASK);

    // ofp_role_request
    TREE_FIELD("ofp_role_request", "Role request");
    FIELD("ofp_role_request.role", "Role", FT_UINT32, BASE_HEX, VALUES(ofp_controller_role), NO_MASK);
    FIELD("ofp_role_request.generation_id", "Generation ID", FT_UINT64, BASE_HEX, NO_VALUES, NO_MASK);

    // ofp_async_config
    TREE_FIELD("ofp_async_config", "Async config");
    BITMAP_FIELD("ofp_async_config.packet_in_mask-eq_ms", "Packet In Mask (for equal, master)", FT_UINT32);
    BITMAP_FIELD("ofp_async_config.packet_in_mask-sl", "Packet In Mask (for slave)", FT_UINT32);
    BITMAP_FIELD("ofp_async_config.port_status_mask-eq_ms", "Port Status Mask (for equal, master)", FT_UINT32);
    BITMAP_FIELD("ofp_async_config.port_status_mask-sl", "Port Status Mask (for slave)", FT_UINT32);
    BITMAP_FIELD("ofp_async_config.flow_removed_mask-eq_ms", "Flow Removed Mask (for equal, master)", FT_UINT32);
    BITMAP_FIELD("ofp_async_config.flow_removed_mask-sl", "Flow Removed Mask (for slave)", FT_UINT32);

    // ofp_meter_mod
    TREE_FIELD("ofp_meter_mod", "Meter Mod");
    FIELD("ofp_meter_mod.command", "Command", FT_UINT16, BASE_DEC, VALUES(ofp_meter_mod_command), NO_MASK);
    FIELD("ofp_meter_mod.flags", "Flags", FT_UINT16, BASE_HEX, VALUES(ofp_meter_flags), NO_MASK);
    FIELD("ofp_meter_mod.meter_id", "Meter ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
    TREE_FIELD("ofp_meter_band", "Band");
    FIELD("ofp_meter_band.type", "Type", FT_UINT16, BASE_HEX, VALUES(ofp_meter_band_type), NO_MASK);
    FIELD("ofp_meter_band.len", "Length", FT_UINT16, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_meter_band.rate", "Rate", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_meter_band.burst_size", "Burst size", FT_UINT32, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_meter_band_dscp_remark.prec_level", "Precedence level", FT_UINT8, BASE_DEC, NO_VALUES, NO_MASK);
    FIELD("ofp_meter_band_experimenter.experimenter", "Experimenter ID", FT_UINT32, BASE_HEX, NO_VALUES, NO_MASK);
}

// Generated code
void DissectorContext::setupCodes(void) {
    // ofp_type
    TYPE_ARRAY(ofp_type);
    TYPE_ARRAY_ADD(ofp_type, OFPT_HELLO, "Hello (SM) - OFPT_HELLO");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ERROR, "Error (SM) - OFPT_ERROR");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ECHO_REQUEST, "Echo request (SM) - OFPT_ECHO_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ECHO_REPLY, "Echo reply (SM) - OFPT_ECHO_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_EXPERIMENTER, "Experimenter message (SM) - OFPT_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_type, OFPT_FEATURES_REQUEST, "Features request (CSM) - OFPT_FEATURES_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_FEATURES_REPLY, "Features reply (CSM) - OFPT_FEATURES_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_GET_CONFIG_REQUEST, "Get config request (CSM) - OFPT_GET_CONFIG_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_GET_CONFIG_REPLY, "Get config reply (CSM) - OFPT_GET_CONFIG_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_SET_CONFIG, "Set config (CSM) - OFPT_SET_CONFIG");
    TYPE_ARRAY_ADD(ofp_type, OFPT_PACKET_IN, "Packet in (AM) - OFPT_PACKET_IN");
    TYPE_ARRAY_ADD(ofp_type, OFPT_FLOW_REMOVED, "Flow removed (AM) - OFPT_FLOW_REMOVED");
    TYPE_ARRAY_ADD(ofp_type, OFPT_PORT_STATUS, "Port status (AM) - OFPT_PORT_STATUS");
    TYPE_ARRAY_ADD(ofp_type, OFPT_PACKET_OUT, "Packet out (CSM) - OFPT_PACKET_OUT");
    TYPE_ARRAY_ADD(ofp_type, OFPT_FLOW_MOD, "Flow mod (CSM) - OFPT_FLOW_MOD");
    TYPE_ARRAY_ADD(ofp_type, OFPT_GROUP_MOD, "Group mod (CSM) - OFPT_GROUP_MOD");
    TYPE_ARRAY_ADD(ofp_type, OFPT_PORT_MOD, "Port mod (CSM) - OFPT_PORT_MOD");
    TYPE_ARRAY_ADD(ofp_type, OFPT_TABLE_MOD, "Table mod (CSM) - OFPT_TABLE_MOD");
    TYPE_ARRAY_ADD(ofp_type, OFPT_MULTIPART_REQUEST, "Multipart request (CSM) - OFPT_MULTIPART_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_MULTIPART_REPLY, "Multipart reply (CSM) - OFPT_MULTIPART_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_BARRIER_REQUEST, "Barrier request (CSM) - OFPT_BARRIER_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_BARRIER_REPLY, "Stats reply (CSM) - OFPT_BARRIER_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_QUEUE_GET_CONFIG_REQUEST, "Queue get config request (CSM) - OFPT_QUEUE_GET_CONFIG_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_QUEUE_GET_CONFIG_REPLY, "Queue get config reply (CSM) - OFPT_QUEUE_GET_CONFIG_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ROLE_REQUEST, "Role request (CSM) - OFPT_ROLE_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_ROLE_REPLY, "Role reply (CSM) - OFPT_ROLE_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_GET_ASYNC_REQUEST, "Async request (CSM) - OFPT_GET_ASYNC_REQUEST");
    TYPE_ARRAY_ADD(ofp_type, OFPT_GET_ASYNC_REPLY, "Async reply (CSM) - OFPT_GET_ASYNC_REPLY");
    TYPE_ARRAY_ADD(ofp_type, OFPT_SET_ASYNC, "Set async (CSM) - OFPT_SET_ASYNC");
    TYPE_ARRAY_ADD(ofp_type, OFPT_METER_MOD, "Meter Mod (CSM) - OFPT_METER_MOD");

    // ofp_port_no
    TYPE_ARRAY(ofp_port_no);
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_MAX, "Maximum number of physical and logical switch ports - OFPP_MAX");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_IN_PORT, "Send the packet out the input port - OFPP_IN_PORT");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_TABLE, "Submit the packet to the first flow table - OFPP_TABLE");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_NORMAL, "Process with normal L2/L3 switching - OFPP_NORMAL");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_FLOOD, "All physical ports in VLAN, except input port and those blocked or link down - OFPP_FLOOD");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_ALL, "All physical ports except input port - OFPP_ALL");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_CONTROLLER, "Send to controller - OFPP_CONTROLLER");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_LOCAL, "Local openflow \"port\" - OFPP_LOCAL");
    TYPE_ARRAY_ADD(ofp_port_no, OFPP_ANY, "Any port. For flow mod (delete) and flow stats requests only - OFPP_ANY");

    // ofp_queue_properties
    TYPE_ARRAY(ofp_queue_properties);
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_MIN_RATE, "Minimum datarate guaranteed - OFPQT_MIN_RATE");
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_MAX_RATE, "Maximum datarate - OFPQT_MAX_RATE");
    TYPE_ARRAY_ADD(ofp_queue_properties, OFPQT_EXPERIMENTER, "Experimenter defined property - OFPQT_EXPERIMENTER");

    // ofp_match_type
    TYPE_ARRAY(ofp_match_type);
    TYPE_ARRAY_ADD(ofp_match_type, OFPMT_STANDARD, "Deprecated - OFPMT_STANDARD");
    TYPE_ARRAY_ADD(ofp_match_type, OFPMT_OXM, "OpenFlow Extensible Match - OFPMT_OXM");

    // ofp_oxm_class
    TYPE_ARRAY(ofp_oxm_class);
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_NXM_0, "Backward compatibility with NXM - OFPXMC_NXM_0");
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_NXM_1, "Backward compatibility with NXM - OFPXMC_NXM_1");
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_OPENFLOW_BASIC, "Basic class for OpenFlow - OFPXMC_OPENFLOW_BASIC");
    TYPE_ARRAY_ADD(ofp_oxm_class, OFPXMC_EXPERIMENTER, "Experimenter class - OFPXMC_EXPERIMENTER");

    // oxm_ofb_match_fields
    TYPE_ARRAY(oxm_ofb_match_fields);
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IN_PORT, "Switch input port - OFPXMT_OFB_IN_PORT");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IN_PHY_PORT, "Switch physical input port - OFPXMT_OFB_IN_PHY_PORT");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_METADATA, "Metadata passed between tables - OFPXMT_OFB_METADATA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ETH_DST, "Ethernet destination address - OFPXMT_OFB_ETH_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ETH_SRC, "Ethernet source address - OFPXMT_OFB_ETH_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ETH_TYPE, "Ethernet frame type - OFPXMT_OFB_ETH_TYPE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_VLAN_VID, "VLAN id - OFPXMT_OFB_VLAN_VID");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_VLAN_PCP, "VLAN priority - OFPXMT_OFB_VLAN_PCP");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IP_DSCP, "IP DSCP (6 bits in ToS field) - OFPXMT_OFB_IP_DSCP");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IP_ECN, "IP ECN (2 bits in ToS field) - OFPXMT_OFB_IP_ECN");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IP_PROTO, "IP protocol - OFPXMT_OFB_IP_PROTO");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV4_SRC, "IPv4 source address - OFPXMT_OFB_IPV4_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV4_DST, "IPv4 destination address - OFPXMT_OFB_IPV4_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_TCP_SRC, "TCP source port - OFPXMT_OFB_TCP_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_TCP_DST, "TCP destination port - OFPXMT_OFB_TCP_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_UDP_SRC, "UDP source port - OFPXMT_OFB_UDP_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_UDP_DST, "UDP destination port - OFPXMT_OFB_UDP_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_SCTP_SRC, "SCTP source port - OFPXMT_OFB_SCTP_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_SCTP_DST, "SCTP destination port - OFPXMT_OFB_SCTP_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV4_TYPE, "ICMP type - OFPXMT_OFB_ICMPV4_TYPE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV4_CODE, "ICMP code - OFPXMT_OFB_ICMPV4_CODE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_OP, "ARP opcode - OFPXMT_OFB_ARP_OP");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_SPA, "ARP source IPv4 address - OFPXMT_OFB_ARP_SPA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_TPA, "ARP target IPv4 address - OFPXMT_OFB_ARP_TPA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_SHA, "ARP source hardware address - OFPXMT_OFB_ARP_SHA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ARP_THA, "ARP target hardware address - OFPXMT_OFB_ARP_THA");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_SRC, "IPv6 source address - OFPXMT_OFB_IPV6_SRC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_DST, "IPv6 destination address - OFPXMT_OFB_IPV6_DST");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_FLABEL, "IPv6 Flow Label - OFPXMT_OFB_IPV6_FLABEL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV6_TYPE, "ICMPv6 type - OFPXMT_OFB_ICMPV6_TYPE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_ICMPV6_CODE, "ICMPv6 code - OFPXMT_OFB_ICMPV6_CODE");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_ND_TARGET, "Target address for ND - OFPXMT_OFB_IPV6_ND_TARGET");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_ND_SLL, "Source link-layer for ND - OFPXMT_OFB_IPV6_ND_SLL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_ND_TLL, "Target link-layer for ND - OFPXMT_OFB_IPV6_ND_TLL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_MPLS_LABEL, "MPLS label - OFPXMT_OFB_MPLS_LABEL");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_MPLS_TC, "MPLS TC - OFPXMT_OFB_MPLS_TC");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFP_MPLS_BOS, "MPLS BoS bit - OFPXMT_OFP_MPLS_BOS");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_PBB_ISID, "PBB I-SID - OFPXMT_OFB_PBB_ISID");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_TUNNEL_ID, "Logical Port Metadata - OFPXMT_OFB_TUNNEL_ID");
    TYPE_ARRAY_ADD(oxm_ofb_match_fields, OFPXMT_OFB_IPV6_EXTHDR, "IPv6 Extension Header pseudo-field - OFPXMT_OFB_IPV6_EXTHDR");

    // ofp_vlan_id
    TYPE_ARRAY(ofp_vlan_id);
    TYPE_ARRAY_ADD(ofp_vlan_id, OFPVID_PRESENT, "Bit that indicate that a VLAN id is set - OFPVID_PRESENT");
    TYPE_ARRAY_ADD(ofp_vlan_id, OFPVID_NONE, "No VLAN id was set - OFPVID_NONE");

    // ofp_instruction_type
    TYPE_ARRAY(ofp_instruction_type);
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_GOTO_TABLE, "Setup the next table in the lookup - OFPIT_GOTO_TABLE");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_WRITE_METADATA, "Setup the metadata field for use later in pipeline - OFPIT_WRITE_METADATA");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_WRITE_ACTIONS, "Write the action(s) onto the datapath action set - OFPIT_WRITE_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_APPLY_ACTIONS, "Applies the action(s) immediately - OFPIT_APPLY_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_CLEAR_ACTIONS, "Clears all actions from the datapath action set - OFPIT_CLEAR_ACTIONS");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_METER, "Apply meter (rate limiter) - OFPIT_METER");
    TYPE_ARRAY_ADD(ofp_instruction_type, OFPIT_EXPERIMENTER, "Experimenter instruction - OFPIT_EXPERIMENTER");

    // ofp_action_type
    TYPE_ARRAY(ofp_action_type);
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_OUTPUT, "Output to switch port - OFPAT_OUTPUT");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_COPY_TTL_OUT, "Copy TTL \"outwards\" -- from next-to-outermost to outermost - OFPAT_COPY_TTL_OUT");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_COPY_TTL_IN, "Copy TTL \"inwards\" -- from outermost to next-to-outermost - OFPAT_COPY_TTL_IN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_MPLS_TTL, "MPLS TTL - OFPAT_SET_MPLS_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_DEC_MPLS_TTL, "Decrement MPLS TTL - OFPAT_DEC_MPLS_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_PUSH_VLAN, "Push a new VLAN tag - OFPAT_PUSH_VLAN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_POP_VLAN, "Pop the outer VLAN tag - OFPAT_POP_VLAN");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_PUSH_MPLS, "Push a new MPLS tag - OFPAT_PUSH_MPLS");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_POP_MPLS, "Pop the outer MPLS tag - OFPAT_POP_MPLS");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_QUEUE, "Set queue id when outputting to a port - OFPAT_SET_QUEUE");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_GROUP, "Apply group - OFPAT_GROUP");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_NW_TTL, "IP TTL - OFPAT_SET_NW_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_DEC_NW_TTL, "Decrement IP TTL - OFPAT_DEC_NW_TTL");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_SET_FIELD, "Set a header field using OXM TLV format - OFPAT_SET_FIELD");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_PUSH_PBB, "Push a new PBB service tag (I-TAG) - OFPAT_PUSH_PBB");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_POP_PBB, "Pop the outer PBB service tag (I-TAG) - OFPAT_POP_PBB");
    TYPE_ARRAY_ADD(ofp_action_type, OFPAT_EXPERIMENTER, "Experimenter action - OFPAT_EXPERIMENTER");

    // ofp_controller_max_len
    TYPE_ARRAY(ofp_controller_max_len);
    TYPE_ARRAY_ADD(ofp_controller_max_len, OFPCML_MAX, "maximum max_len value which can be used to request a specific byte length - OFPCML_MAX");
    TYPE_ARRAY_ADD(ofp_controller_max_len, OFPCML_NO_BUFFER, "indicates that no buffering should be applied and the whole packet is to be sent to the controller - OFPCML_NO_BUFFER");

    // ofp_table
    TYPE_ARRAY(ofp_table);
    TYPE_ARRAY_ADD(ofp_table, OFPTT_MAX, "Last usable table number - OFPTT_MAX");
    TYPE_ARRAY_ADD(ofp_table, OFPTT_ALL, "Wildcard table used for table config flow stats and flow deletes - OFPTT_ALL");

    // ofp_flow_mod_command
    TYPE_ARRAY(ofp_flow_mod_command);
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_ADD, "New flow - OFPFC_ADD");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY, "Modify all matching flows - OFPFC_MODIFY");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_MODIFY_STRICT, "Modify entry strictly matching wildcards and priority - OFPFC_MODIFY_STRICT");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE, "Delete all matching flows - OFPFC_DELETE");
    TYPE_ARRAY_ADD(ofp_flow_mod_command, OFPFC_DELETE_STRICT, "Delete entry strictly matching wildcards and priority - OFPFC_DELETE_STRICT");

    // ofp_group
    TYPE_ARRAY(ofp_group);
    TYPE_ARRAY_ADD(ofp_group, OFPG_MAX, "Last usable group number - OFPG_MAX");
    TYPE_ARRAY_ADD(ofp_group, OFPG_ALL, "Represents all groups for group delete commands - OFPG_ALL");
    TYPE_ARRAY_ADD(ofp_group, OFPG_ANY, "Wildcard group used only for flow stats requests. Selects all flows regardless of group (including flows with no group) - OFPG_ANY");

    // ofp_group_mod_command
    TYPE_ARRAY(ofp_group_mod_command);
    TYPE_ARRAY_ADD(ofp_group_mod_command, OFPGC_ADD, "New group - OFPGC_ADD");
    TYPE_ARRAY_ADD(ofp_group_mod_command, OFPGC_MODIFY, "Modify all matching groups - OFPGC_MODIFY");
    TYPE_ARRAY_ADD(ofp_group_mod_command, OFPGC_DELETE, "Delete all matching groups - OFPGC_DELETE");

    // ofp_group_type
    TYPE_ARRAY(ofp_group_type);
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_ALL, "All (multicast/broadcast) group - OFPGT_ALL");
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_SELECT, "Select group - OFPGT_SELECT");
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_INDIRECT, "Indirect group - OFPGT_INDIRECT");
    TYPE_ARRAY_ADD(ofp_group_type, OFPGT_FF, "Fast failover group - OFPGT_FF");

    // ofp_controller_role
    TYPE_ARRAY(ofp_controller_role);
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_NOCHANGE, "Don’t change current role - OFPCR_ROLE_NOCHANGE");
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_EQUAL, "Default role, full access - OFPCR_ROLE_EQUAL");
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_MASTER, "Full access, at most one master - OFPCR_ROLE_MASTER");
    TYPE_ARRAY_ADD(ofp_controller_role, OFPCR_ROLE_SLAVE, "Read-only access - OFPCR_ROLE_SLAVE");

    // ofp_packet_in_reason
    TYPE_ARRAY(ofp_packet_in_reason);
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_NO_MATCH, "No matching flow - OFPR_NO_MATCH");
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_ACTION, "Action explicitly output to controller - OFPR_ACTION");
    TYPE_ARRAY_ADD(ofp_packet_in_reason, OFPR_INVALID_TTL, "Packet has invalid TTL - OFPR_INVALID_TTL");

    // ofp_flow_removed_reason
    TYPE_ARRAY(ofp_flow_removed_reason);
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_IDLE_TIMEOUT, "Flow idle time exceeded idle_timeout - OFPRR_IDLE_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_HARD_TIMEOUT, "Time exceeded hard_timeout - OFPRR_HARD_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_DELETE, "Evicted by a DELETE flow mod - OFPRR_DELETE");
    TYPE_ARRAY_ADD(ofp_flow_removed_reason, OFPRR_GROUP_DELETE, "Group was removed - OFPRR_GROUP_DELETE");

    // ofp_port_reason
    TYPE_ARRAY(ofp_port_reason);
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_ADD, "The port was added - OFPPR_ADD");
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_DELETE, "The port was removed - OFPPR_DELETE");
    TYPE_ARRAY_ADD(ofp_port_reason, OFPPR_MODIFY, "Some attribute of the port has changed - OFPPR_MODIFY");

    // ofp_error_type
    TYPE_ARRAY(ofp_error_type);
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_HELLO_FAILED, "Hello protocol failed - OFPET_HELLO_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_REQUEST, "Request was not understood - OFPET_BAD_REQUEST");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_ACTION, "Error in action description - OFPET_BAD_ACTION");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_INSTRUCTION, "Error in instruction list - OFPET_BAD_INSTRUCTION");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_BAD_MATCH, "Error in match - OFPET_BAD_MATCH");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_FLOW_MOD_FAILED, "Problem modifying flow entry - OFPET_FLOW_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_GROUP_MOD_FAILED, "Problem modifying group entry - OFPET_GROUP_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_PORT_MOD_FAILED, "Port mod request failed - OFPET_PORT_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_TABLE_MOD_FAILED, "Table mod request failed - OFPET_TABLE_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_QUEUE_OP_FAILED, "Queue operation failed - OFPET_QUEUE_OP_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_SWITCH_CONFIG_FAILED, "Switch config request failed - OFPET_SWITCH_CONFIG_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_ROLE_REQUEST_FAILED, "Controller Role request failed - OFPET_ROLE_REQUEST_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_METER_MOD_FAILED, "Error in meter - OFPET_METER_MOD_FAILED");
    TYPE_ARRAY_ADD(ofp_error_type, OFPET_EXPERIMENTER, "Experimenter error messages - OFPET_EXPERIMENTER");

    // ofp_hello_failed_code
    TYPE_ARRAY(ofp_hello_failed_code);
    TYPE_ARRAY_ADD(ofp_hello_failed_code, OFPHFC_INCOMPATIBLE, "No compatible version - OFPHFC_INCOMPATIBLE");
    TYPE_ARRAY_ADD(ofp_hello_failed_code, OFPHFC_EPERM, "Permissions error - OFPHFC_EPERM");

    // ofp_bad_request_code
    TYPE_ARRAY(ofp_bad_request_code);
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_VERSION, "ofp_header.version not supported - OFPBRC_BAD_VERSION");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_TYPE, "ofp_header.type not supported - OFPBRC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_MULTIPART, "ofp_multipart_request.type not supported - OFPBRC_BAD_MULTIPART");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_EXPERIMENTER, "Experimenter id not supported - OFPBRC_BAD_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_EXP_TYPE, "Experimenter type not supported - OFPBRC_BAD_EXP_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_EPERM, "Permissions error - OFPBRC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_LEN, "Wrong request length for type - OFPBRC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_EMPTY, "Specified buffer has already been used - OFPBRC_BUFFER_EMPTY");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BUFFER_UNKNOWN, "Specified buffer does not exist - OFPBRC_BUFFER_UNKNOWN");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_TABLE_ID, "Specified table-id invalid or does not exist - OFPBRC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_IS_SLAVE, "Denied because controller is slave - OFPBRC_IS_SLAVE");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_PORT, "Invalid port - OFPBRC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_BAD_PACKET, "Invalid packet in packet-out - OFPBRC_BAD_PACKET");
    TYPE_ARRAY_ADD(ofp_bad_request_code, OFPBRC_MULTIPART_BUFFER_OVERFLOW, "ofp_multipart_request overflowed the assigned buffer - OFPBRC_MULTIPART_BUFFER_OVERFLOW");

    // ofp_bad_action_code
    TYPE_ARRAY(ofp_bad_action_code);
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_TYPE, "Unknown action type - OFPBAC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_LEN, "Length problem in actions - OFPBAC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_EXPERIMENTER, "Unknown experimenter id specified - OFPBAC_BAD_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_EXP_TYPE, "Unknown action for experimenter id - OFPBAC_BAD_EXP_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_OUT_PORT, "Problem validating output port - OFPBAC_BAD_OUT_PORT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_ARGUMENT, "Bad action argument - OFPBAC_BAD_ARGUMENT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_EPERM, "Permissions error - OFPBAC_EPERM");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_TOO_MANY, "Can’t handle this many actions - OFPBAC_TOO_MANY");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_QUEUE, "Problem validating output queue - OFPBAC_BAD_QUEUE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_OUT_GROUP, "Invalid group id in forward action - OFPBAC_BAD_OUT_GROUP");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_MATCH_INCONSISTENT, "Action can’t apply for this match or Set-Field missing prerequisite - OFPBAC_MATCH_INCONSISTENT");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_UNSUPPORTED_ORDER, "Action order is unsupported for the action list in an Apply-Actions instruction - OFPBAC_UNSUPPORTED_ORDER");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_TAG, "Actions uses an unsupported tag/encap - OFPBAC_BAD_TAG");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_SET_TYPE, "Unsupported type in SET_FIELD action - OFPBAC_BAD_SET_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_SET_LEN, "Length problem in SET_FIELD action - OFPBAC_BAD_SET_LEN");
    TYPE_ARRAY_ADD(ofp_bad_action_code, OFPBAC_BAD_SET_ARGUMENT, "Bad argument in SET_FIELD action - OFPBAC_BAD_SET_ARGUMENT");

    // ofp_bad_instruction_code
    TYPE_ARRAY(ofp_bad_instruction_code);
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNKNOWN_INST, "Unknown instruction - OFPBIC_UNKNOWN_INST");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_INST, "Switch or table does not support the instruction - OFPBIC_UNSUP_INST");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_TABLE_ID, "Invalid Table-ID specified - OFPBIC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_METADATA, "Metadata value unsupported by datapath - OFPBIC_UNSUP_METADATA");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_UNSUP_METADATA_MASK, "Metadata mask value unsupported by datapath - OFPBIC_UNSUP_METADATA_MASK");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_EXPERIMENTER, "Unknown experimenter id specified - OFPBIC_BAD_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_EXP_TYPE, "Unknown instruction for experimenter id - OFPBIC_BAD_EXP_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_BAD_LEN, "Length problem in instructions - OFPBIC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_instruction_code, OFPBIC_EPERM, "Permissions error - OFPBIC_EPERM");

    // ofp_bad_match_code
    TYPE_ARRAY(ofp_bad_match_code);
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_TYPE, "Unsupported match type specified by the match - OFPBMC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_LEN, "Length problem in match - OFPBMC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_TAG, "Match uses an unsupported tag/encap - OFPBMC_BAD_TAG");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_DL_ADDR_MASK, "Unsupported datalink addr mask - switch does not support arbitrary datalink address mask - OFPBMC_BAD_DL_ADDR_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_NW_ADDR_MASK, "Unsupported network addr mask - switch does not support arbitrary network address mask - OFPBMC_BAD_NW_ADDR_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_WILDCARDS, "Unsupported combination of fields masked or omitted in the match - OFPBMC_BAD_WILDCARDS");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_FIELD, "Unsupported field type in the match - OFPBMC_BAD_FIELD");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_VALUE, "Unsupported value in a match field - OFPBMC_BAD_VALUE");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_MASK, "Unsupported mask specified in the match, field is not dl-address or nw-address - OFPBMC_BAD_MASK");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_BAD_PREREQ, "A prerequisite was not met - OFPBMC_BAD_PREREQ");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_DUP_FIELD, "A field type was duplicated - OFPBMC_DUP_FIELD");
    TYPE_ARRAY_ADD(ofp_bad_match_code, OFPBMC_EPERM, "Permissions error - OFPBMC_EPERM");

    // ofp_flow_mod_failed_code
    TYPE_ARRAY(ofp_flow_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_UNKNOWN, "Unspecified error - OFPFMFC_UNKNOWN");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_TABLE_FULL, "Flow not added because table was full - OFPFMFC_TABLE_FULL");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_TABLE_ID, "Table does not exist - OFPFMFC_BAD_TABLE_ID");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_OVERLAP, "Attempted to add overlapping flow with CHECK_OVERLAP flag set - OFPFMFC_OVERLAP");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_EPERM, "Permissions error - OFPFMFC_EPERM");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_TIMEOUT, "Flow not added because of unsupported idle/hard timeout - OFPFMFC_BAD_TIMEOUT");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_COMMAND, "Unsupported or unknown command - OFPFMFC_BAD_COMMAND");
    TYPE_ARRAY_ADD(ofp_flow_mod_failed_code, OFPFMFC_BAD_FLAGS, "Unsupported or unknown flags - OFPFMFC_BAD_FLAGS");

    // ofp_group_mod_failed_code
    TYPE_ARRAY(ofp_group_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_GROUP_EXISTS, "Group not added because a group ADD attempted to replace an already-present group - OFPGMFC_GROUP_EXISTS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_INVALID_GROUP, "Group not added because Group - OFPGMFC_INVALID_GROUP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_OUT_OF_GROUPS, "The group table is full - OFPGMFC_OUT_OF_GROUPS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_OUT_OF_BUCKETS, "The maximum number of action buckets for a group has been exceeded - OFPGMFC_OUT_OF_BUCKETS");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_CHAINING_UNSUPPORTED, "Switch does not support groups that forward to groups - OFPGMFC_CHAINING_UNSUPPORTED");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_WATCH_UNSUPPORTED, "This group cannot watch the watch_port or watch_group specified - OFPGMFC_WATCH_UNSUPPORTED");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_LOOP, "Group entry would cause a loop - OFPGMFC_LOOP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_UNKNOWN_GROUP, "Group not modified because a group MODIFY attempted to modify a non-existent group - OFPGMFC_UNKNOWN_GROUP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_CHAINED_GROUP, "Group not deleted because another group is forwarding to it - OFPGMFC_CHAINED_GROUP");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_TYPE, "Unsupported or unknown group type - OFPGMFC_BAD_TYPE");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_COMMAND, "Unsupported or unknown command - OFPGMFC_BAD_COMMAND");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_BUCKET, "Error in bucket - OFPGMFC_BAD_BUCKET");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_BAD_WATCH, "Error in watch port/group - OFPGMFC_BAD_WATCH");
    TYPE_ARRAY_ADD(ofp_group_mod_failed_code, OFPGMFC_EPERM, "Permissions error - OFPGMFC_EPERM");

    // ofp_port_mod_failed_code
    TYPE_ARRAY(ofp_port_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_PORT, "Specified port number does not exist - OFPPMFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_HW_ADDR, "Specified hardware address does not match the port number - OFPPMFC_BAD_HW_ADDR");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_CONFIG, "Specified config is invalid - OFPPMFC_BAD_CONFIG");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_BAD_ADVERTISE, "Specified advertise is invalid - OFPPMFC_BAD_ADVERTISE");
    TYPE_ARRAY_ADD(ofp_port_mod_failed_code, OFPPMFC_EPERM, "Permissions error - OFPPMFC_EPERM");

    // ofp_table_mod_failed_code
    TYPE_ARRAY(ofp_table_mod_failed_code);
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_BAD_TABLE, "Specified table does not exist - OFPTMFC_BAD_TABLE");
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_BAD_CONFIG, "Specified config is invalid - OFPTMFC_BAD_CONFIG");
    TYPE_ARRAY_ADD(ofp_table_mod_failed_code, OFPTMFC_EPERM, "Permissions error - OFPTMFC_EPERM");

    // ofp_multipart_types
    TYPE_ARRAY(ofp_multipart_types);
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_DESC, "Description of this OpenFlow switch - OFPMP_DESC");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_FLOW, "Individual flow statistics - OFPMP_FLOW");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_AGGREGATE, "Aggregate flow statistics - OFPMP_AGGREGATE");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_TABLE, "Flow table statistics - OFPMP_TABLE");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_PORT_STATS, "Port statistics - OFPMP_PORT_STATS");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_QUEUE, "Queue statistics for a port - OFPMP_QUEUE");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_GROUP, "Group counter statistics - OFPMP_GROUP");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_GROUP_DESC, "Group description statistics - OFPMP_GROUP_DESC");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_GROUP_FEATURES, "Group features - OFPMP_GROUP_FEATURES");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_METER, "Meter statistics - OFPMP_METER");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_METER_CONFIG, "Meter configuration - OFPMP_METER_CONFIG");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_METER_FEATURES, "Meter features - OFPMP_METER_FEATURES");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_TABLE_FEATURES, "Table features - OFPMP_TABLE_FEATURES");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_PORT_DESC, "Port description - OFPMP_PORT_DESC");
    TYPE_ARRAY_ADD(ofp_multipart_types, OFPMP_EXPERIMENTER, "Experimenter extension - OFPMP_EXPERIMENTER");

    // ofp_table_feature_prop_type
    TYPE_ARRAY(ofp_table_feature_prop_type);
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_INSTRUCTIONS, "Instructions property - OFPTFPT_INSTRUCTIONS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_INSTRUCTIONS_MISS, "Instructions for table-miss - OFPTFPT_INSTRUCTIONS_MISS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_NEXT_TABLES, "Next Table property - OFPTFPT_NEXT_TABLES");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_NEXT_TABLES_MISS, "Next Table for table-miss - OFPTFPT_NEXT_TABLES_MISS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_WRITE_ACTIONS, "Write Actions property - OFPTFPT_WRITE_ACTIONS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_WRITE_ACTIONS_MISS, "Write Actions for table-miss - OFPTFPT_WRITE_ACTIONS_MISS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_APPLY_ACTIONS, "Apply Actions property - OFPTFPT_APPLY_ACTIONS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_APPLY_ACTIONS_MISS, "Apply Actions for table-miss - OFPTFPT_APPLY_ACTIONS_MISS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_MATCH, "Match property - OFPTFPT_MATCH");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_WILDCARDS, "Wildcards property - OFPTFPT_WILDCARDS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_WRITE_SETFIELD, "Write Set-Field property - OFPTFPT_WRITE_SETFIELD");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_WRITE_SETFIELD_MISS, "Write Set-Field for table-miss - OFPTFPT_WRITE_SETFIELD_MISS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_APPLY_SETFIELD, "Apply Set-Field property - OFPTFPT_APPLY_SETFIELD");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_APPLY_SETFIELD_MISS, "Apply Set-Field for table-miss - OFPTFPT_APPLY_SETFIELD_MISS");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_EXPERIMENTER, "Experimenter property - OFPTFPT_EXPERIMENTER");
    TYPE_ARRAY_ADD(ofp_table_feature_prop_type, OFPTFPT_EXPERIMENTER_MISS, "Experimenter for table-miss - OFPTFPT_EXPERIMENTER_MISS");

    // ofp_queue_op_failed_code
    TYPE_ARRAY(ofp_queue_op_failed_code);
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_PORT, "Invalid port (or port does not exist) - OFPQOFC_BAD_PORT");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_BAD_QUEUE, "Queue does not exist - OFPQOFC_BAD_QUEUE");
    TYPE_ARRAY_ADD(ofp_queue_op_failed_code, OFPQOFC_EPERM, "Permissions error - OFPQOFC_EPERM");

    // ofp_switch_config_failed_code
    TYPE_ARRAY(ofp_switch_config_failed_code);
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPSCFC_BAD_FLAGS, "Specified flags is invalid - OFPSCFC_BAD_FLAGS");
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPSCFC_BAD_LEN, "Specified len is invalid - OFPSCFC_BAD_LEN");
    TYPE_ARRAY_ADD(ofp_switch_config_failed_code, OFPQCFC_EPERM, "Permissions error - OFPQCFC_EPERM");

    // ofp_role_request_failed_code
    TYPE_ARRAY(ofp_role_request_failed_code);
    TYPE_ARRAY_ADD(ofp_role_request_failed_code, OFPRRFC_STALE, "Stale Message: old generation_id - OFPRRFC_STALE");
    TYPE_ARRAY_ADD(ofp_role_request_failed_code, OFPRRFC_UNSUP, "Controller role change unsupported - OFPRRFC_UNSUP");
    TYPE_ARRAY_ADD(ofp_role_request_failed_code, OFPRRFC_BAD_ROLE, "Invalid role - OFPRRFC_BAD_ROLE");

    // ofp_meter
    TYPE_ARRAY(ofp_meter);
    TYPE_ARRAY_ADD(ofp_meter, OFPM_MAX, "Last usable meter - OFPM_MAX");
    TYPE_ARRAY_ADD(ofp_meter, OFPM_SLOWPATH, "Meter for slow datapath, if any - OFPM_SLOWPATH");
    TYPE_ARRAY_ADD(ofp_meter, OFPM_CONTROLLER, "Meter for controller connection - OFPM_CONTROLLER");
    TYPE_ARRAY_ADD(ofp_meter, OFPM_ALL, "Represents all meters for stat requests commands - OFPM_ALL");

    // ofp_meter_mod_command
    TYPE_ARRAY(ofp_meter_mod_command);
    TYPE_ARRAY_ADD(ofp_meter_mod_command, OFPMC_ADD, "New meter - OFPMC_ADD");
    TYPE_ARRAY_ADD(ofp_meter_mod_command, OFPMC_MODIFY, "Modify specified meter - OFPMC_MODIFY");
    TYPE_ARRAY_ADD(ofp_meter_mod_command, OFPMC_DELETE, "Delete specified meter - OFPMC_DELETE");

    // ofp_meter_flags
    TYPE_ARRAY(ofp_meter_flags);
    TYPE_ARRAY_ADD(ofp_meter_flags, OFPMF_KBPS, "Rate value in kb/s (kilo-bit per second) - OFPMF_KBPS");
    TYPE_ARRAY_ADD(ofp_meter_flags, OFPMF_PKTPS, "Rate value in packet/sec - OFPMF_PKTPS");
    TYPE_ARRAY_ADD(ofp_meter_flags, OFPMF_BURST, "Do burst size - OFPMF_BURST");
    TYPE_ARRAY_ADD(ofp_meter_flags, OFPMF_STATS, "Collect statistics - OFPMF_STATS");

    // ofp_meter_band_type
    TYPE_ARRAY(ofp_meter_band_type);
    TYPE_ARRAY_ADD(ofp_meter_band_type, OFPMBT_DROP, "Drop packet - OFPMBT_DROP");
    TYPE_ARRAY_ADD(ofp_meter_band_type, OFPMBT_DSCP_REMARK, "Remark DSCP in the IP header - OFPMBT_DSCP_REMARK");
    TYPE_ARRAY_ADD(ofp_meter_band_type, OFPMBT_EXPERIMENTER, "Experimenter meter band - OFPMBT_EXPERIMENTER");

}


void DissectorContext::setupFlags(void) {
    // ofp_port_config
    BITMAP_PART("ofp_port_config.OFPPC_PORT_DOWN", "Port is administratively down", 32, OFPPC_PORT_DOWN);
    BITMAP_PART("ofp_port_config.OFPPC_NO_RECV", "Drop all packets received by port", 32, OFPPC_NO_RECV);
    BITMAP_PART("ofp_port_config.OFPPC_NO_FWD", "Drop packets forwarded to port", 32, OFPPC_NO_FWD);
    BITMAP_PART("ofp_port_config.OFPPC_NO_PACKET_IN", "Do not send packet-in msgs for port", 32, OFPPC_NO_PACKET_IN);
    BITMAP_PART("ofp_port_config.RESERVED", "Reserved", 32, 0xffffff9a);

    // ofp_port_state
    BITMAP_PART("ofp_port_state.OFPPS_LINK_DOWN", "No physical link present", 32, OFPPS_LINK_DOWN);
    BITMAP_PART("ofp_port_state.OFPPS_BLOCKED", "Port is blocked", 32, OFPPS_BLOCKED);
    BITMAP_PART("ofp_port_state.OFPPS_LIVE", "Live for Fast Failover Group", 32, OFPPS_LIVE);
    BITMAP_PART("ofp_port_state.RESERVED", "Reserved", 32, 0xfffffff8);

    // ofp_port_features
    BITMAP_PART("ofp_port_features.OFPPF_10MB_HD", "10 Mb half-duplex rate support", 32, OFPPF_10MB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_10MB_FD", "10 Mb full-duplex rate support", 32, OFPPF_10MB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_100MB_HD", "100 Mb half-duplex rate support", 32, OFPPF_100MB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_100MB_FD", "100 Mb full-duplex rate support", 32, OFPPF_100MB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_1GB_HD", "1 Gb half-duplex rate support", 32, OFPPF_1GB_HD);
    BITMAP_PART("ofp_port_features.OFPPF_1GB_FD", "1 Gb full-duplex rate support", 32, OFPPF_1GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_10GB_FD", "10 Gb full-duplex rate support", 32, OFPPF_10GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_40GB_FD", "40 Gb full-duplex rate support", 32, OFPPF_40GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_100GB_FD", "100 Gb full-duplex rate support", 32, OFPPF_100GB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_1TB_FD", "1 Tb full-duplex rate support", 32, OFPPF_1TB_FD);
    BITMAP_PART("ofp_port_features.OFPPF_OTHER", "Other rate, not in the list", 32, OFPPF_OTHER);
    BITMAP_PART("ofp_port_features.OFPPF_COPPER", "Copper medium", 32, OFPPF_COPPER);
    BITMAP_PART("ofp_port_features.OFPPF_FIBER", "Fiber medium", 32, OFPPF_FIBER);
    BITMAP_PART("ofp_port_features.OFPPF_AUTONEG", "Auto-negotiation", 32, OFPPF_AUTONEG);
    BITMAP_PART("ofp_port_features.OFPPF_PAUSE", "Pause", 32, OFPPF_PAUSE);
    BITMAP_PART("ofp_port_features.OFPPF_PAUSE_ASYM", "Asymmetric pause", 32, OFPPF_PAUSE_ASYM);
    BITMAP_PART("ofp_port_features.RESERVED", "Reserved", 32, 0xffff0000);

    // ofp_capabilities
    BITMAP_PART("ofp_capabilities.OFPC_FLOW_STATS", "Flow statistics", 32, OFPC_FLOW_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_TABLE_STATS", "Table statistics", 32, OFPC_TABLE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_PORT_STATS", "Port statistics", 32, OFPC_PORT_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_GROUP_STATS", "Group statistics", 32, OFPC_GROUP_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_IP_REASM", "Can reassemble IP fragments", 32, OFPC_IP_REASM);
    BITMAP_PART("ofp_capabilities.OFPC_QUEUE_STATS", "Queue statistics", 32, OFPC_QUEUE_STATS);
    BITMAP_PART("ofp_capabilities.OFPC_PORT_BLOCKED", "Switch will block looping ports", 32, OFPC_PORT_BLOCKED);
    BITMAP_PART("ofp_capabilities.RESERVED", "Reserved", 32, 0xfffffe90);

    // ofp_config_flags
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_DROP", "Drop fragments", 16, OFPC_FRAG_DROP);
    BITMAP_PART("ofp_config_flags.OFPC_FRAG_REASM", "Reassemble (only if OFPC_IP_REASM set)", 16, OFPC_FRAG_REASM);
    BITMAP_PART("ofp_config_flags.OFPC_INVALID_TTL_TO_CONTROLLER", "Send packets with invalid TTL to the controller", 16, OFPC_INVALID_TTL_TO_CONTROLLER);
    BITMAP_PART("ofp_config_flags.RESERVED", "Reserved", 16, 0xfff8);

    // ofp_table_config

    BITMAP_PART("ofp_table_config.RESERVED", "Reserved", 32, 0xffffffff);

    // ofp_flow_mod_flags
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_SEND_FLOW_REM", "Send flow removed message when flow expires or is deleted", 16, OFPFF_SEND_FLOW_REM);
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_CHECK_OVERLAP", "Check for overlapping entries first", 16, OFPFF_CHECK_OVERLAP);
    BITMAP_PART("ofp_flow_mod_flags.OFPFF_RESET_COUNTS", "Reset flow packet and byte counts", 16, OFPFF_RESET_COUNTS);
    BITMAP_PART("ofp_flow_mod_flags.RESERVED", "Reserved", 16, 0xfff8);

    // ofp_group_capabilities
    BITMAP_PART("ofp_group_capabilities.OFPGFC_SELECT_WEIGHT", "Support weight for select groups", 32, OFPGFC_SELECT_WEIGHT);
    BITMAP_PART("ofp_group_capabilities.OFPGFC_SELECT_LIVENESS", "Support liveness for select groups", 32, OFPGFC_SELECT_LIVENESS);
    BITMAP_PART("ofp_group_capabilities.OFPGFC_CHAINING", "Support chaining groups", 32, OFPGFC_CHAINING);
    BITMAP_PART("ofp_group_capabilities.OFPGFC_CHAINING_CHECKS", "Check chaining for loops and delete", 32, OFPGFC_CHAINING_CHECKS);
    BITMAP_PART("ofp_group_capabilities.RESERVED", "Reserved", 32, 0xfffffff0);

    // ofp_packet_in_reason_bitmask
    BITMAP_PART("ofp_packet_in_reason_bitmask.OFPR_NO_MATCH", "No matching flow", 32, 1 << OFPR_NO_MATCH);
    BITMAP_PART("ofp_packet_in_reason_bitmask.OFPR_ACTION", "Action explicitly output to controller", 32, 1 << OFPR_ACTION);
    BITMAP_PART("ofp_packet_in_reason_bitmask.OFPR_INVALID_TTL", "Packet has invalid TTL", 32, 1 << OFPR_INVALID_TTL);
    BITMAP_PART("ofp_packet_in_reason_bitmask.RESERVED", "Reserved", 32, 0xfffffff8);

    // ofp_flow_removed_reason_bitmask
    BITMAP_PART("ofp_flow_removed_reason_bitmask.OFPRR_IDLE_TIMEOUT", "Flow idle time exceeded idle_timeout", 32, 1 << OFPRR_IDLE_TIMEOUT);
    BITMAP_PART("ofp_flow_removed_reason_bitmask.OFPRR_HARD_TIMEOUT", "Time exceeded hard_timeout", 32, 1 << OFPRR_HARD_TIMEOUT);
    BITMAP_PART("ofp_flow_removed_reason_bitmask.OFPRR_DELETE", "Evicted by a DELETE flow mod", 32, 1 << OFPRR_DELETE);
    BITMAP_PART("ofp_flow_removed_reason_bitmask.OFPRR_GROUP_DELETE", "Group was removed", 32, 1 << OFPRR_GROUP_DELETE);
    BITMAP_PART("ofp_flow_removed_reason_bitmask.RESERVED", "Reserved", 32, 0xfffffff0);

    // ofp_port_reason_bitmask
    BITMAP_PART("ofp_port_reason_bitmask.OFPPR_ADD", "The port was added", 32, 1 << OFPPR_ADD);
    BITMAP_PART("ofp_port_reason_bitmask.OFPPR_DELETE", "The port was removed", 32, 1 << OFPPR_DELETE);
    BITMAP_PART("ofp_port_reason_bitmask.OFPPR_MODIFY", "Some attribute of the port has changed", 32, 1 << OFPPR_MODIFY);
    BITMAP_PART("ofp_port_reason_bitmask.RESERVED", "Reserved", 32, 0xfffffff8);

    // ofp_multipart_request_flags
    BITMAP_PART("ofp_multipart_request_flags.OFPMPF_REQ_MORE", "More requests to follow", 16, OFPMPF_REQ_MORE);
    BITMAP_PART("ofp_multipart_request_flags.RESERVED", "Reserved", 16, 0xfffe);

    // ofp_multipart_reply_flags
    BITMAP_PART("ofp_multipart_reply_flags.OFPMPF_REPLY_MORE", "More replies to follow", 16, OFPMPF_REPLY_MORE);
    BITMAP_PART("ofp_multipart_reply_flags.RESERVED", "Reserved", 16, 0xfffe);

}

}
