/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#define OPENFLOW_INTERNAL

#include <openflow-common.hpp>
#include <of10/openflow-100.hpp>
#include <of11/openflow-110.hpp>
#include <of12/openflow-120.hpp>
#include <of13/openflow-130.hpp>

#include <glib.h>
#include <epan/packet.h>
#include <epan/ftypes/ftypes.h>

static int proto_openflow = -1;

static dissector_handle_t data_handle = NULL;
static dissector_handle_t openflow_handle;

static gint ofp = -1;
static gint ofp_header = -1;


void
dissect_openflow (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
  {
  if (tvb_length(tvb) < OFP_MIN_PACKET_SIZE) // This isn't openflow
    return;

  guint8 version = tvb_get_guint8(tvb, 0);
  switch (version)
    {
    case OFP_100_NS::gVersion:
      OFP_100_NS::Context->dissect(tvb, pinfo, tree);
      break;
    case OFP_110_NS::gVersion:
      OFP_110_NS::Context->dissect(tvb, pinfo, tree);
      break;
    case OFP_120_NS::gVersion:
      OFP_120_NS::Context->dissect(tvb, pinfo, tree);
      break;
    case OFP_130_NS::gVersion:
      OFP_130_NS::Context->dissect(tvb, pinfo, tree);
      break;
    default:
      return;
    }
  }

void
proto_reg_handoff_openflow (void)
  {
  static bool initialized = false;

  if (!initialized)
    {
    data_handle = find_dissector("data");
    openflow_handle = create_dissector_handle(dissect_openflow, proto_openflow);
    dissector_add("tcp.port", OFP_TCP_PORT, openflow_handle);
    dissector_add("tcp.port", 43984, openflow_handle);
    OFP_100_NS::Context->setHandles(data_handle, openflow_handle);
    OFP_110_NS::Context->setHandles(data_handle, openflow_handle);
    OFP_120_NS::Context->setHandles(data_handle, openflow_handle);
    OFP_130_NS::Context->setHandles(data_handle, openflow_handle);
    }
  }

void
proto_register_openflow (void)
  {
  proto_openflow = proto_register_protocol("OpenFlow Protocol", "OFP", "of");

  OFP_100_NS::init(proto_openflow);
  OFP_110_NS::init(proto_openflow);
  OFP_120_NS::init(proto_openflow);
  OFP_130_NS::init(proto_openflow);

  register_dissector("openflow", dissect_openflow, proto_openflow);
  }
