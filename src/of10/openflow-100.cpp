/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#define OPENFLOW_INTERNAL

#include <of10/openflow-100.hpp>
#include <openflow-common.hpp>

#if defined(__cplusplus)
extern "C" {
#endif

#include <epan/dissectors/packet-tcp.h>

#if defined(__cplusplus)
}
#endif

#define PROTO_TAG_OPENFLOW_VER "OFP 1.0"

namespace openflow_100
  {
  DissectorContext * DissectorContext::mSingle = NULL;
  DissectorContext * Context;

  DissectorContext::DissectorContext (int proto_openflow)
    : mProtoOpenflow(proto_openflow)
    {
    Context = this;
    }

  void
  DissectorContext::dissect (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
    {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, DissectorContext::getMessageLen, DissectorContext::dissectMessage);
    }

  void
  DissectorContext::setHandles (dissector_handle_t data, dissector_handle_t openflow)
    {
    this->mDataHandle = data;
    this->mOpenflowHandle = openflow;
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
  DissectorContext::dissectMessage (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
    {
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_OPENFLOW_VER);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);
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

