/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#ifndef HDR_FIELDMANAGER_HPP
#define HDR_FIELDMANAGER_HPP

#include <openflow-common.hpp>

#include <string>
#include <map>

void addValueString(GArray *array, guint32 value, const gchar *str);

/*! Class to manage fields for treeview display and searching in Wireshark GUI.
*/
class FieldManager {
    public:
    /*!
    \param proto Protocol ID for all fields managed by this object.
    \param key_prefix Prefix for all keys managed by this object, usually a protocol abbreviation.
    */
    FieldManager(int proto, std::string key_prefix);

    /*!
    \details Method used to create fields to be used in the UI for display and searching.
    Dotted hierarchy for key strings (outer.inner.val) is recommended and supported for organization.

    \param key Key string you will use to refer to this field internally.
    \param name Field name for display in the UI.
    \param type Field Type (from Wireshark).
    \param display
    \param strings
    \param bitmask
    \param subtree Whether to create this field as a subtree with children in the UI.
    */
    void createField(std::string key, 
                     const char *name, 
                     ftenum type, 
                     int display,
                     const void *strings, 
                     guint32 bitmask, 
                     bool subtree = false);
    /*!
    Performs final registration of all fields created earlier.

    \warning You may only call this method once, so make sure you have created all fields in all codepaths
    before using this method.
    */
    void doRegister(void);

    /*!
    Adds a named subtree to the given parent covering the bytes specified.

    \param parent Parent tree pointer
    \param key Key named used in \link FieldManager::createField \endlink
    \param tvb Current packet buffer
    \param start Starting byte position in the packet buffer for the data in this subtree
    \param len Length of the packet data consumed by this subtree
    */
    proto_tree* addSubtree(proto_tree* parent, std::string key, tvbuff_t *tvb, guint32 start, guint32 len);

    /*!
    \details Adds a named item to the given parent tree.
    The format of the data is determined by the arguments supplied to \link FieldManager::createField \endlink.

    \param parent Parent tree pointer
    \param key Key named used in \link FieldManager::createField \endlink
    \param tvb Current packet buffer
    \param start Starting byte position in the packet buffer for the data in this item
    \param len Length of the packet data covering this item
    */
    void addItem(proto_tree* parent, std::string key, tvbuff_t *tvb, guint32 start, guint32 len);

    /*!
    \details Adds a boolean item to the given parent tree.
    Generally called multiple times on the same value as the rendered portion will be determined by the
    bitmask specified in the \link FieldManager::createField \endlink method.  Unlike
    \link FieldManager::addItem \endlink, this method does not extract the data from the packet for you,
    as it needs to inspect it multiple times.

    \param parent Parent tree pointer
    \param key Key named used in \link FieldManager::createField \endlink
    \param tvb Current packet buffer
    \param start Starting byte position in the packet buffer for the data in this item
    \param len Length of the packet data covering this item
    \param value The value against which to apply the bitmask.
    */
    proto_item* addBoolean(proto_tree* parent, std::string key, tvbuff_t *tvb, guint32 start, guint32 len, guint32 value);

    /*!
    \details Adds a subdisector to the given parent tree.
    The format of the data is determined by the arguments supplied to \link FieldManager::createField \endlink.

    \param parent Parent tree pointer
    \param key Key named used in \link FieldManager::createField \endlink
    \param tvb Current packet buffer
    \param pinfo Current packet info
    \param handle Dissector Handle
    \param start Starting byte position in the packet buffer for the data in this item
    \param len Length of the packet data covering this item
    \param reported_len Length of the packet before truncation
    */
    void addDissector(proto_tree* parent, std::string key, tvbuff_t *tvb, packet_info *pinfo, dissector_handle_t handle, guint32 start, guint32 len, guint32 reported_len);

    private:
    std::map<std::string, gint*>  mFields;
    std::map<std::string, gint*>  mSubtrees;

    GArray*       mFieldArray;
    GArray*       mTreeArray;

    int           mProto;
    std::string   mKeyPrefix;
};

#endif
