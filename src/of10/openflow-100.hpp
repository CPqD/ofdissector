/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#ifndef HDR_OPENFLOW_100_HPP
#define HDR_OPENFLOW_100_HPP

#define OFP_100_NS  openflow_100

#include <openflow-common.hpp>

namespace openflow_100
  {
  static const guint16  gVersion = 0x01;

  class DLLEXPORT DissectorContext
    {
  public:
    static DissectorContext *   getInstance (int);
    static guint                getMessageLen (packet_info *, tvbuff_t *, int);
    static void                 dissectMessage (tvbuff_t *, packet_info *, proto_tree *);

    void    setHandles (dissector_handle_t, dissector_handle_t);

    void    dissect (tvbuff_t *, packet_info *, proto_tree *);

  private:
    DissectorContext (int);

    dissector_handle_t        mDataHandle;
    dissector_handle_t        mOpenflowHandle;
    int                       mProtoOpenflow;

    static DissectorContext *mSingle;
    };

  extern DissectorContext * Context;

  void  init (int);
  }

#endif // Header guard
