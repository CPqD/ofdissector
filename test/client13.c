#include "net.h"
#include "of13.h"
#include <stdint.h>

#define FALSE 0
#define TRUE 1

#define UINT8 8
#define UINT16 16
#define UINT32 32
#define UINT64 64

/* Creates a message struct with the given length at variable name */
#define MESSAGE(name) \
    MSG name; \
    name.data = NULL; \
    name.offset = 0;

/* Appropriate hton based on lenght */
#define HTON(length, value) hton##length(value)
/* uint*_t type based on length */
#define TYPE(length) uint##length##_t
/* Packs a value of the given length to a message */
#define PACK(msg, name, value, length) \
    msg.data = realloc(msg.data, msg.offset + length/8); \
    *((TYPE(length)*) (msg.data + msg.offset)) = HTON(length, value); \
    msg.offset += length/8
/* Adds a padding of the given length to a message */
#define PADDING(msg, length) \
    msg.data = realloc(msg.data, msg.offset + length); \
    memset(msg.data + msg.offset, 0, length); \
    msg.offset += length
/* Sets the ofp_header length property based on message length */
#define SET_OFP_HEADER_LENGTH(msg) \
    *((uint16_t*) msg.data + 1) =  hton16(msg.offset)
/* Prepares and sends the message */
#define SEND(name) SET_OFP_HEADER_LENGTH(name); net_send(name);


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

/* Rename types for a prettier code */
typedef struct ofp_header OFP_HEADER;
typedef struct ofp_header OFP_MATCH;
typedef struct ofp_flow_mod OFP_FLOW_MOD;
typedef struct ofp_instruction_actions OFP_INSTRUCTION_ACTIONS;
typedef struct ofp_action_output OFP_ACTION_OUTPUT;
typedef struct ofp_action_mpls_label OFP_ACTION_MPLS_LABEL;

/* A containter for a message with progressive packing */
typedef struct msg {
    void* data;
    uint16_t offset;
} MSG;

/* Sends a message through the socket */
void net_send(MSG msg) {
    int sockfd, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("Error opening socket");
    server = gethostbyname(HOST);
    if (server == NULL) {
        fprintf(stderr,"Error, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(PORT);
    if (connect(sockfd,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("Error connecting");

    n = write(sockfd, msg.data, msg.offset);
    if (n < 0)
         error("Error writing to socket");

    close(sockfd);
}

int main(int argc, char *argv[])
{
    MESSAGE(msg0);
    PACK(msg0, "ofp_multipart_reply.header.version", OFP_VERSION, UINT8);
    PACK(msg0, "ofp_multipart_reply.header.type", OFPT_MULTIPART_REQUEST, UINT8);
    PACK(msg0, "ofp_multipart_reply.header.length", 0, UINT16);
    PACK(msg0, "ofp_multipart_reply.header.xid", 0xabababab, UINT32);
    PACK(msg0, "ofp_multipart_reply.type", OFPMP_TABLE_FEATURES, UINT16);
    PACK(msg0, "ofp_multipart_reply.flags", 0, UINT16);
    PADDING(msg0, 4);
    PACK(msg0, "ofp_multipart_reply.body.length", 120, UINT16);
    PACK(msg0, "ofp_multipart_reply.body.table_id", 0, UINT8);
    PADDING(msg0, 5);
    PACK(msg0, "ofp_multipart_reply.body.name[0]", 0x7468697320697320, UINT64);
    PACK(msg0, "ofp_multipart_reply.body.name[0]", 0x6120746573740000, UINT64);
    PACK(msg0, "ofp_multipart_reply.body.name[0]", 0, UINT64);
    PACK(msg0, "ofp_multipart_reply.body.name[0]", 0, UINT64);
    PACK(msg0, "ofp_multipart_reply.body.metadata_match", 1, UINT64);
    PACK(msg0, "ofp_multipart_reply.body.metadata_write", 2, UINT64);
    PACK(msg0, "ofp_multipart_reply.body.config", OFPTC_TABLE_MISS_CONTINUE & OFPTC_TABLE_MISS_DROP, UINT32);
    PACK(msg0, "ofp_multipart_reply.body.maxentries", 256, UINT32);
        PACK(msg0, "ofp_multipart_reply.body[0].type", OFPTFPT_INSTRUCTIONS, UINT16);
        PACK(msg0, "ofp_multipart_reply.body[0].length", 12, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[0][0].type", OFPIT_APPLY_ACTIONS, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[0][0].length", 4, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[0][1].type", OFPIT_GOTO_TABLE, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[0][1].length", 4, UINT16);
        PADDING(msg0, OFP_MATCH_OXM_PADDING(12));

        PACK(msg0, "ofp_multipart_reply.body[1].type", OFPTFPT_NEXT_TABLES, UINT16);
        PACK(msg0, "ofp_multipart_reply.body[1].length", 7, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[1][0]", 2, UINT8);
            PACK(msg0, "ofp_multipart_reply.body[1][2]", 12, UINT8);
            PACK(msg0, "ofp_multipart_reply.body[1][2]", 22, UINT8);
        PADDING(msg0, OFP_MATCH_OXM_PADDING(7));

        PACK(msg0, "ofp_multipart_reply.body[2].type", OFPTFPT_WRITE_ACTIONS_MISS, UINT16);
        PACK(msg0, "ofp_multipart_reply.body[2].length", 16, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[2][0].type", OFPAT_OUTPUT, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[2][0].length", 4, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[2][1].type", OFPAT_SET_FIELD, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[2][1].length", 4, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[2][2].type", OFPAT_POP_VLAN, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[2][2].length", 4, UINT16);
        PADDING(msg0, OFP_MATCH_OXM_PADDING(16));

        PACK(msg0, "ofp_multipart_reply.body[3].type", OFPTFPT_APPLY_SETFIELD, UINT16);
        PACK(msg0, "ofp_multipart_reply.body[3].length", 12, UINT16);
            PACK(msg0, "ofp_multipart_reply.body[3][0]", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IN_PORT, TRUE, 0), UINT32);
            PACK(msg0, "ofp_multipart_reply.body[3][1]", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_DST, TRUE, 0), UINT32);
        PADDING(msg0, OFP_MATCH_OXM_PADDING(12));
    SEND(msg0);

    MESSAGE(msg1);
    PACK(msg1, "ofp_flow_mod.header.version", OFP_VERSION, UINT8);
    PACK(msg1, "ofp_flow_mod.header.type", OFPT_FLOW_MOD, UINT8);
    PACK(msg1, "ofp_flow_mod.header.length", 0, UINT16); // We don't know the length yet
    PACK(msg1, "ofp_flow_mod.header.xid", 0xcafebabe, UINT32);
    PACK(msg1, "ofp_flow_mod.cookie", 0xdeadbeef, UINT64);
    PACK(msg1, "ofp_flow_mod.cookie_mask", 0x01, UINT64);
    PACK(msg1, "ofp_flow_mod.table_id", 0, UINT8);
    PACK(msg1, "ofp_flow_mod.command", OFPFC_ADD, UINT8);
    PACK(msg1, "ofp_flow_mod.idle_timeout", 15, UINT16);
    PACK(msg1, "ofp_flow_mod.hard_timeout", 30, UINT16);
    PACK(msg1, "ofp_flow_mod.priority", 12345, UINT16);
    PACK(msg1, "ofp_flow_mod.buffer_id", 4, UINT32);
    PACK(msg1, "ofp_flow_mod.out_port", OFPP_ANY, UINT32);
    PACK(msg1, "ofp_flow_mod.out_group", OFPG_ANY, UINT32);
    PACK(msg1, "ofp_flow_mod.flags", OFPFF_CHECK_OVERLAP, UINT16);
    PADDING(msg1, 2);
    PACK(msg1, "ofp_flow_mod.match.type", OFPMT_OXM, UINT16);
    PACK(msg1, "ofp_flow_mod.match.length", 28, UINT16);
        PACK(msg1, "ofp_flow_mod.match.oxm_fields[0].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IN_PORT, TRUE, 64), UINT32);
        PACK(msg1, "ofp_flow_mod.match.oxm_fields[0].value", 789, UINT32);
        PACK(msg1, "ofp_flow_mod.match.oxm_fields[0].mask", 0x12345678, UINT32);
        PACK(msg1, "ofp_flow_mod.match.oxm_fields[1].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_DST, TRUE, 64), UINT32);
        PACK(msg1, "ofp_flow_mod.match.oxm_fields[1].value", 0xc0a80001, UINT32);
        PACK(msg1, "ofp_flow_mod.match.oxm_fields[1].mask", 0xFFFFFF00, UINT32);
    PADDING(msg1, OFP_MATCH_OXM_PADDING(28));
    PACK(msg1, "ofp_flow_mod.instructions[0].type", OFPIT_APPLY_ACTIONS, UINT16);
    PACK(msg1, "ofp_flow_mod.instructions[0].len", 48, UINT16);
    PADDING(msg1, 4);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[0].type", OFPAT_OUTPUT, UINT16);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[0].len", 16, UINT16);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[0].port", 456, UINT32);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[0].max_len", 90, UINT16);
        PADDING(msg1, 6);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[1].type", OFPAT_SET_FIELD, UINT16);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[1].len", 16, UINT16);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[1].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_TCP_SRC, FALSE, 16), UINT32);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[1].value", 456, UINT16);
        PADDING(msg1, OFP_ACTION_SET_FIELD_OXM_PADDING(6));
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[2].type", OFPAT_POP_VLAN, UINT16);
        PACK(msg1, "ofp_flow_mod.instructions[0].actions[2].len", 8, UINT16);
        PADDING(msg1, 4);
    PACK(msg1, "ofp_flow_mod.instructions[1].type", OFPIT_METER, UINT16);
    PACK(msg1, "ofp_flow_mod.instructions[1].len", 8, UINT16);
    PACK(msg1, "ofp_flow_mod.instructions[1].meter_id", 1234, UINT32);
    SEND(msg1); // Now we pack the length correctly and send the message

    MESSAGE(msg2);
    PACK(msg2, "ofp_packet_in.header.version", OFP_VERSION, UINT8);
    PACK(msg2, "ofp_packet_in.header.type", OFPT_PACKET_IN, UINT8);
    PACK(msg2, "ofp_packet_in.header.length", 0, UINT16);
    PACK(msg2, "ofp_packet_in.header.xid", 0xcafebabe, UINT32);
    PACK(msg2, "ofp_packet_in.buffer_id", 0xdeadbeef, UINT32);
    PACK(msg2, "ofp_packet_in.total_len", 0x1234, UINT16);
    PACK(msg2, "ofp_packet_in.reason", OFPR_ACTION, UINT8);
    PACK(msg2, "ofp_packet_in.table_id", 0xAA, UINT8);
    PACK(msg2, "ofp_packet_in.cookie", 0xbeefbeef, UINT64);
    PACK(msg2, "ofp_packet_in.match.type", OFPMT_OXM, UINT16);
    PACK(msg2, "ofp_packet_in.match.length", 28, UINT16);
    PACK(msg2, "ofp_packet_in.match.oxm_fields[0].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IN_PORT, TRUE, 64), UINT32);
    PACK(msg2, "ofp_packet_in.match.oxm_fields[0].value", 789, UINT32);
    PACK(msg2, "ofp_packet_in.match.oxm_fields[0].mask", 0x12345678, UINT32);
    PACK(msg2, "ofp_packet_in.match.oxm_fields[1].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_DST, TRUE, 64), UINT32);
    PACK(msg2, "ofp_packet_in.match.oxm_fields[1].value", 0xc0a80001, UINT32);
    PACK(msg2, "ofp_packet_in.match.oxm_fields[1].mask", 0xFFFFFF00, UINT32);
    PADDING(msg2, OFP_MATCH_OXM_PADDING(28));
    PADDING(msg2, 2);
    PACK(msg2, "ofp_packet_in.data", 0x0, UINT64);
    SEND(msg2);

    MESSAGE(msg3);
    PACK(msg3, "ofp_packet_out.header.version", OFP_VERSION, UINT8);
    PACK(msg3, "ofp_packet_out.header.type", OFPT_PACKET_OUT, UINT8);
    PACK(msg3, "ofp_packet_out.header.length", 0, UINT16);
    PACK(msg3, "ofp_packet_out.header.xid", 0xcafebabe, UINT32);
    PACK(msg3, "ofp_packet_out.buffer_id", 0xdeadbeef, UINT32);
    PACK(msg3, "ofp_packet_out.in_port", 0x12345678, UINT32);
    PACK(msg3, "ofp_packet_out.actions_len", 16, UINT16);
    PADDING(msg3, 6);
    PACK(msg3, "ofp_packet_out.actions[0].type", OFPAT_OUTPUT, UINT16);
    PACK(msg3, "ofp_packet_out.actions[0].len", 16, UINT16);
    PACK(msg3, "ofp_packet_out.actions[0].port", 456, UINT32);
    PACK(msg3, "ofp_packet_out.actions[0].max_len", 90, UINT16);
    PADDING(msg3, 6);
    PACK(msg3, "ofp_packet_out.data", 0x080808, UINT64);
    SEND(msg3);

    MESSAGE(msg4);
    PACK(msg4, "ofp_role_request.header.version", OFP_VERSION, UINT8);
    PACK(msg4, "ofp_role_request.header.type", OFPT_ROLE_REPLY, UINT8);
    PACK(msg4, "ofp_role_request.header.length", 0, UINT16);
    PACK(msg4, "ofp_role_request.header.xid", 0xcafebabe, UINT32);
    PACK(msg4, "ofp_role_request.role", OFPCR_ROLE_MASTER, UINT32);
    PADDING(msg4, 4);
    PACK(msg4, "ofp_role_request.generation_id", 0x0102030405060708, UINT64);
    SEND(msg4);

    MESSAGE(msg5);
    PACK(msg5, "ofp_error.header.version", OFP_VERSION, UINT8);
    PACK(msg5, "ofp_error.header.type", OFPT_ERROR, UINT8);
    PACK(msg5, "ofp_error.header.length", 0, UINT16);
    PACK(msg5, "ofp_error.header.xid", 0xcafebabe, UINT32);
    PACK(msg5, "ofp_error.type", OFPET_BAD_MATCH, UINT16);
    PACK(msg5, "ofp_error.code", OFPBMC_BAD_FIELD, UINT16);
    PACK(msg5, "ofp_error.data", 0xdeaddeaddeaddead, UINT64);
    SEND(msg5);

    MESSAGE(msg6);
    PACK(msg6, "ofp_switch_features.header.version", OFP_VERSION, UINT8);
    PACK(msg6, "ofp_switch_features.header.type", OFPT_FEATURES_REPLY, UINT8);
    PACK(msg6, "ofp_switch_features.header.length", 0, UINT16);
    PACK(msg6, "ofp_switch_features.header.xid", 0xcafebabe, UINT32);
    PACK(msg6, "ofp_switch_features.datapath_id", 0xcafecafecafecafe, UINT64);
    PACK(msg6, "ofp_switch_features.n_buffers", 1000, UINT32);
    PACK(msg6, "ofp_switch_features.n_tables", 100, UINT8);
    PADDING(msg6, 3);
    PACK(msg6, "ofp_switch_features.capabilities", OFPC_TABLE_STATS | OFPC_IP_REASM, UINT32);
    PACK(msg6, "ofp_switch_features.reserved", 0x0, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].port_no", 0x0, UINT32);
    PADDING(msg6, 4);
    PACK(msg6, "ofp_switch_features.ports[0].hw_addr[0]", 0xa, UINT8);
    PACK(msg6, "ofp_switch_features.ports[0].hw_addr[1]", 0xb, UINT8);
    PACK(msg6, "ofp_switch_features.ports[0].hw_addr[2]", 0xc, UINT8);
    PACK(msg6, "ofp_switch_features.ports[0].hw_addr[3]", 0xd, UINT8);
    PACK(msg6, "ofp_switch_features.ports[0].hw_addr[4]", 0xe, UINT8);
    PACK(msg6, "ofp_switch_features.ports[0].hw_addr[5]", 0xf, UINT8);
    PADDING(msg6, 2);
    PACK(msg6, "ofp_switch_features.ports[0].name", 0xabcdef1234567890, UINT64);
    PACK(msg6, "ofp_switch_features.ports[0].name", 0xabcdef1234567890, UINT64);
    PACK(msg6, "ofp_switch_features.ports[0].config", OFPPC_NO_FWD | OFPPC_NO_PACKET_IN, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].state", OFPPS_LIVE, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].curr", OFPPF_OTHER, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].advertised", OFPPF_OTHER, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].supported", OFPPF_OTHER, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].peer", OFPPF_OTHER, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].curr_speed", 5000, UINT32);
    PACK(msg6, "ofp_switch_features.ports[0].max_speed", 20000, UINT32);
    SEND(msg6);

    MESSAGE(msg7);
    PACK(msg7, "ofp_switch_config.header.version", OFP_VERSION, UINT8);
    PACK(msg7, "ofp_switch_config.header.type", OFPT_GET_CONFIG_REPLY, UINT8);
    PACK(msg7, "ofp_switch_config.header.length", 0, UINT16);
    PACK(msg7, "ofp_switch_config.header.xid", 0xcafebabe, UINT32);
    PACK(msg7, "ofp_switch_config.flags", OFPC_FRAG_DROP | OFPC_INVALID_TTL_TO_CONTROLLER, UINT16);
    PACK(msg7, "ofp_switch_config.miss_send_len", 4321, UINT16);
    SEND(msg7);

    MESSAGE(msg8);
    PACK(msg8, "ofp_table_mod.header.version", OFP_VERSION, UINT8);
    PACK(msg8, "ofp_table_mod.header.type", OFPT_TABLE_MOD, UINT8);
    PACK(msg8, "ofp_table_mod.header.length", 0, UINT16);
    PACK(msg8, "ofp_table_mod.header.xid", 0xcafebabe, UINT32);
    PACK(msg8, "ofp_table_mod.table_id", 99, UINT8);
    PADDING(msg8, 3);
    PACK(msg8, "ofp_table_mod.config", 0, UINT32);
    SEND(msg8);

    MESSAGE(msg9);
    PACK(msg9, "ofp_get_async_request.header.version", OFP_VERSION, UINT8);
    PACK(msg9, "ofp_get_async_request.header.type", OFPT_GET_ASYNC_REQUEST, UINT8);
    PACK(msg9, "ofp_get_async_request.header.length", 0, UINT16);
    PACK(msg9, "ofp_get_async_request.header.xid", 0xcafebabe, UINT32);
    SEND(msg9);

    MESSAGE(msg10);
    PACK(msg10, "ofp_get_async_reply.header.version", OFP_VERSION, UINT8);
    PACK(msg10, "ofp_get_async_reply.header.type", OFPT_SET_ASYNC, UINT8);
    PACK(msg10, "ofp_get_async_reply.header.length", 0, UINT16);
    PACK(msg10, "ofp_get_async_reply.header.xid", 0xcafebabe, UINT32);
    PACK(msg10, "ofp_get_async_reply.packet_in_mask[0]", 0b011, UINT32);
    PACK(msg10, "ofp_get_async_reply.packet_in_mask[1]", 0b100, UINT32);
    PACK(msg10, "ofp_get_async_reply.port_status_mask[0]", 0b001, UINT32);
    PACK(msg10, "ofp_get_async_reply.port_status_mask[1]", 0b110, UINT32);
    PACK(msg10, "ofp_get_async_reply.flow_removed_mask[0]", 0b1100, UINT32);
    PACK(msg10, "ofp_get_async_reply.flow_removed_mask[1]", 0b0011, UINT32);
    SEND(msg10);

    MESSAGE(msg11);
    PACK(msg11, "ofp_meter_mod.header.version", OFP_VERSION, UINT8);
    PACK(msg11, "ofp_meter_mod.header.type", OFPT_METER_MOD, UINT8);
    PACK(msg11, "ofp_meter_mod.header.length", 0, UINT16);
    PACK(msg11, "ofp_meter_mod.header.xid", 0xcafebabe, UINT32);
    PACK(msg11, "ofp_meter_mod.command", OFPMC_MODIFY, UINT16);
    PACK(msg11, "ofp_meter_mod.flags", OFPMF_BURST, UINT16);
    PACK(msg11, "ofp_meter_mod.meter_id", 0x55556666, UINT32);
    PACK(msg11, "ofp_meter_mod.bands[0].type", OFPMBT_DSCP_REMARK, UINT16);
    PACK(msg11, "ofp_meter_mod.bands[0].length", 16, UINT16);
    PACK(msg11, "ofp_meter_mod.bands[0].rate", 777, UINT32);
    PACK(msg11, "ofp_meter_mod.bands[0].burst_size", 888, UINT32);
    PACK(msg11, "ofp_meter_mod.bands[0].prec_level", 99, UINT8);
    PADDING(msg11, 3);
    SEND(msg11);

    MESSAGE(msg12);
    PACK(msg12, "ofp_flow_stats_request.header.version", OFP_VERSION, UINT8);
    PACK(msg12, "ofp_flow_stats_request.header.type", OFPT_MULTIPART_REQUEST, UINT8);
    PACK(msg12, "ofp_flow_stats_request.header.length", 0, UINT16);
    PACK(msg12, "ofp_flow_stats_request.header.xid", 0xabababab, UINT32);
    PACK(msg12, "ofp_flow_stats_request.type", OFPMP_FLOW, UINT16);
    PACK(msg12, "ofp_flow_stats_request.flags", 0, UINT16);
    PADDING(msg12, 4);
    PACK(msg12, "ofp_flow_stats_request.body.table_id", 59, UINT8);
    PADDING(msg12, 3);
    PACK(msg12, "ofp_flow_stats_request.body.out_port", 41, UINT32);
    PACK(msg12, "ofp_flow_stats_request.body.out_group", 32, UINT32);
    PADDING(msg12, 4);
    PACK(msg12, "ofp_flow_stats_request.body.cookie", 0xdeadbeef, UINT64);
    PACK(msg12, "ofp_flow_stats_request.body.cookie_mask", 0x01, UINT64);
    PACK(msg12, "ofp_flow_stats_request.body.match.type", OFPMT_OXM, UINT16);
    PACK(msg12, "ofp_flow_stats_request.body.match.length", 28, UINT16);
        PACK(msg12, "ofp_flow_stats_request.body.match.oxm_fields[0].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IN_PORT, TRUE, 64), UINT32);
        PACK(msg12, "ofp_flow_stats_request.body.match.oxm_fields[0].value", 789, UINT32);
        PACK(msg12, "ofp_flow_stats_request.body.match.oxm_fields[0].mask", 0x12345678, UINT32);
        PACK(msg12, "ofp_flow_stats_request.body.match.oxm_fields[1].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_DST, TRUE, 64), UINT32);
        PACK(msg12, "ofp_flow_stats_request.body.match.oxm_fields[1].value", 0xc0a80001, UINT32);
        PACK(msg12, "ofp_flow_stats_request.body.match.oxm_fields[1].mask", 0xFFFFFF00, UINT32);
    PADDING(msg12, OFP_MATCH_OXM_PADDING(28));
    SEND(msg12);


    MESSAGE(msg13);
    PACK(msg13, "ofp_flow_stats.header.version", OFP_VERSION, UINT8);
    PACK(msg13, "ofp_flow_stats.header.type", OFPT_MULTIPART_REPLY, UINT8);
    PACK(msg13, "ofp_flow_stats.header.length", 0, UINT16);
    PACK(msg13, "ofp_flow_stats.header.xid", 0xabababab, UINT32);
    PACK(msg13, "ofp_flow_stats.type", OFPMP_FLOW, UINT16);
    PACK(msg13, "ofp_flow_stats.flags", 0, UINT16);
    PADDING(msg13, 4);
    // ofp_flow_stats len, discounted from the basic match, added by our match with padding, followed by two instructions
    PACK(msg13, "ofp_flow_stats.length", sizeof(struct ofp_flow_stats) - 8 + 28 + OFP_MATCH_OXM_PADDING(28) + 48 + 8, UINT16);
    PACK(msg13, "ofp_flow_stats.table_id", 7, UINT8);
    PADDING(msg13, 1);
    PACK(msg13, "ofp_flow_stats.duration_sec", 92819, UINT32);
    PACK(msg13, "ofp_flow_stats.duration_nsec", 31232, UINT32);
    PACK(msg13, "ofp_flow_stats.priority", 12345, UINT16);
    PACK(msg13, "ofp_flow_stats.idle_timeout", 15, UINT16);
    PACK(msg13, "ofp_flow_stats.hard_timeout", 30, UINT16);
    PACK(msg13, "ofp_flow_stats.flags", OFPFF_CHECK_OVERLAP, UINT16);
    PADDING(msg13, 4);
    PACK(msg13, "ofp_flow_stats.cookie", 0xdeadbeef, UINT64);
    PACK(msg13, "ofp_flow_stats.packet_count", 987623, UINT64);
    PACK(msg13, "ofp_flow_stats.byte_count", 301230232, UINT64);
    PACK(msg13, "ofp_flow_stats.match.type", OFPMT_OXM, UINT16);
    PACK(msg13, "ofp_flow_stats.match.length", 28, UINT16);
        PACK(msg13, "ofp_flow_stats.match.oxm_fields[0].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IN_PORT, TRUE, 64), UINT32);
        PACK(msg13, "ofp_flow_stats.match.oxm_fields[0].value", 789, UINT32);
        PACK(msg13, "ofp_flow_stats.match.oxm_fields[0].mask", 0x12345678, UINT32);
        PACK(msg13, "ofp_flow_stats.match.oxm_fields[1].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_IPV4_DST, TRUE, 64), UINT32);
        PACK(msg13, "ofp_flow_stats.match.oxm_fields[1].value", 0xc0a80001, UINT32);
        PACK(msg13, "ofp_flow_stats.match.oxm_fields[1].mask", 0xFFFFFF00, UINT32);
    PADDING(msg13, OFP_MATCH_OXM_PADDING(28));
    PACK(msg13, "ofp_flow_stats.instructions[0].type", OFPIT_APPLY_ACTIONS, UINT16);
    PACK(msg13, "ofp_flow_stats.instructions[0].len", 48, UINT16);
    PADDING(msg13, 4);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[0].type", OFPAT_OUTPUT, UINT16);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[0].len", 16, UINT16);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[0].port", 456, UINT32);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[0].max_len", 90, UINT16);
        PADDING(msg13, 6);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[1].type", OFPAT_SET_FIELD, UINT16);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[1].len", 16, UINT16);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[1].header", OXM_HEADER(OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_TCP_SRC, FALSE, 16), UINT32);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[1].value", 456, UINT16);
        PADDING(msg13, OFP_ACTION_SET_FIELD_OXM_PADDING(6));
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[2].type", OFPAT_POP_VLAN, UINT16);
        PACK(msg13, "ofp_flow_stats.instructions[0].actions[2].len", 8, UINT16);
        PADDING(msg13, 4);
    PACK(msg13, "ofp_flow_stats.instructions[1].type", OFPIT_METER, UINT16);
    PACK(msg13, "ofp_flow_stats.instructions[1].len", 8, UINT16);
    PACK(msg13, "ofp_flow_stats.instructions[1].meter_id", 1234, UINT32);
    SEND(msg13); // Now we pack the length correctly and send the message
    return 0;
}
