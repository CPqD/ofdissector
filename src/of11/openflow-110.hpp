/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#ifndef HDR_OPENFLOW_110_HPP
#define HDR_OPENFLOW_110_HPP

#define OFP_110_NS  openflow_110

#include <openflow-common.hpp>

#include <util/FieldManager.hpp>

// Wireshark isn't a C++ application, so don't try
// to initialize C++ objects before main()

namespace openflow_110
  {
  static const guint16  gVersion = 0x02;

  const true_false_string tfs_set_notset = {"Set", "Not set"};

  class DLLEXPORT DissectorContext 
    {
  public:
    static DissectorContext *   getInstance (int);
    static guint                getMessageLen (packet_info *, tvbuff_t *, int);
    static void                 prepDissect (tvbuff_t *, packet_info *, proto_tree *);

    void    setHandles (dissector_handle_t, dissector_handle_t);

    void    dissect (tvbuff_t *, packet_info *, proto_tree *);

  private:
    DissectorContext (int);

    void      addType (guint32 value, const gchar *str);
    void      addStatsRqType (guint32 value, const gchar *str);
    void      addStatsRpType (guint32 value, const gchar *str);
    void      addErrorType (guint32 value, const gchar *str);
    void      addErrHelloCode (guint32 value, const gchar *str);
    void      addErrBadRequestCode (guint32 value, const gchar *str);
    void      addErrBadActionCode (guint32 value, const gchar *str);
    void      addErrFMFailedCode (guint32 value, const gchar *str);
    void      addErrGMFailedCode (guint32 value, const gchar *str);
    void      addErrPMFailedCode (guint32 value, const gchar *str);
    void      addErrTMFailedCode (guint32 value, const gchar *str);
    void      addErrQOFailedCode (guint32 value, const gchar *str);
    void      addErrSCFailedCode (guint32 value, const gchar *str);
    void      addPortReason (guint32 value, const gchar *str);
    void      addFMCommand (guint32 value, const gchar *str);
    void      addInstType (guint32 value, const gchar *str);
    void      addGMCommand (guint32 value, const gchar *str);
    void      addGroupType (guint32 value, const gchar *str);

    void      addChild (proto_item *, const char *, guint32);
    void      addBoolean (proto_tree *, const char *, guint32, guint32);
    void      consumeBytes (guint32);
    void      addValueString (GArray *, guint32, const gchar*);

    void      setupTypes (void);
    void      setupFields (void);
    void      setupStatsTypes (void);
    void      setupErrorTypes (void);
    void      setupPortReasonTypes (void);
    void      setupGroupModTypes (void);

    void      dispatchMessage (tvbuff_t *, packet_info *, proto_tree *);
    void      dissectError (void);
    void      dissectEcho (void);
    void      dissectFeaturesRequest (void);
    void      dissectFeaturesReply (void);
    void      dissectGetSetConfig (void);
    void      dissectStatsRequest (void);
    void      dissectStatsReply (void);
    void      dissectFlowRemove (void);
    void      dissectPortStatus (void);
    void      dissectFlowMod (void);
    void      dissectTableMod (void);
    void      dissectGroupMod (void);

    void      dissectFlowMatch (proto_tree *);
    void      dissectPort (proto_tree *);
    void      dissectOFPPC (proto_tree *, std::string);
    void      dissectOFPPS (proto_tree *, std::string);
    void      dissectOFPPF (proto_tree *, std::string);
    void      dissectInstruction (proto_tree *);
    void      dissectAction (proto_tree *);
    void      dissectGroupBucket (proto_tree *);

    dissector_handle_t        mDataHandle;
    dissector_handle_t        mOpenflowHandle;
    int                       mProtoOpenflow;
    FieldManager              mFM;

    GArray    *mTypeArray;
    GArray    *mStatsRqArray;
    GArray    *mStatsRpArray;

    GArray    *mErrorTypeArray;
    GArray    *mErrHelloArray;
    GArray    *mErrBadRqArray;
    GArray    *mErrBadActionArray;
    GArray    *mErrFMFailArray;
    GArray    *mErrGMFailArray;
    GArray    *mErrPMFailArray;
    GArray    *mErrTMFailArray;
    GArray    *mErrQOFailArray;
    GArray    *mErrSCFailArray;

    GArray    *mPortRTypeArray;
    GArray    *mFlowModCommandArray;
    GArray    *mInstTypeArray;
    GArray    *mGMCommandArray;
    GArray    *mGTArray;

    // Temporary context for dissection
    tvbuff_t    *_tvb;
    packet_info *_pinfo;
    proto_tree  *_tree;
    guint32     _offset;
    guint32     _rawLen;
    guint16     _oflen;
    proto_tree  *_curOFPSubtree;

    static DissectorContext *mSingle;
    };

  void    init (int);

  extern DissectorContext * Context;
  }

#endif // Header guard
