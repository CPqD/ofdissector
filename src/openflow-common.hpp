/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#ifndef HDR_OPENFLOW_COMMON_HPP
#define HDR_OPENFLOW_COMMON_HPP

#if defined(__cplusplus)
extern "C" {
#endif

#include <config.h>

#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "openflow"

#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */
#define VERSION "0.3+dev"

// Really wireshark, you couldn't extern your symbols?
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

#if defined(__cplusplus)
}
#endif

#if defined(_WIN32)
# if defined(OPENFLOW_INTERNAL)
#   ifndef DLLEXPORT
#     define DLLEXPORT __declspec(dllexport)
#   endif
#   ifndef DLLIMPORT
#      define DLLIMPORT __declspec(dllimport)
#   endif
# endif
#endif

#ifndef DLLEXPORT
# define DLLEXPORT
#endif
#ifndef DLLIMPORT
# define DLLIMPORT
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define PROTO_TAG_OPENFLOW "OFP"
#define OFP_MIN_PACKET_SIZE 8
#define OFP_TCP_PORT 6633

void  DLLEXPORT dissect_openflow (tvbuff_t *, packet_info *, proto_tree *);
void  DLLEXPORT proto_reg_handoff_openflow (void);
void  DLLEXPORT proto_register_openflow (void);

#if defined(__cplusplus)
}
#endif

#endif // Header guard
