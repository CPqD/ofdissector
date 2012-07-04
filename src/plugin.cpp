/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#include <openflow-common.hpp>

#ifndef ENABLE_STATIC

#include <gmodule.h>

/* Start the functions we need for the plugin stuff */

extern "C" G_MODULE_EXPORT const gchar version[] = VERSION;

#if defined(__cplusplus)
extern "C" {
#endif

G_MODULE_EXPORT void
plugin_register (void)
  {
  proto_register_openflow();
  }

G_MODULE_EXPORT void
plugin_reg_handoff(void)
  {
  proto_reg_handoff_openflow();
  }

#if defined(__cplusplus)
}
#endif

#endif
