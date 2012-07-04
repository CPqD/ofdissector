/* Copyright (c) 2010-2011 The Board of Trustees of The Leland Stanford Junior University */

#include <util/FieldManager.hpp>

#include <string.h> // For memset()
#include <iostream>

FieldManager::FieldManager (int proto, std::string key_prefix) : mProto(proto), mKeyPrefix(key_prefix) {
    this->mFieldArray = g_array_new(FALSE, FALSE, sizeof(hf_register_info));
    this->mTreeArray = g_array_new(FALSE, FALSE, sizeof(gint*));
}

void FieldManager::createField (std::string key, const char *name, ftenum type, int display, const void *strings, guint32 bitmask, bool subtree) {
    gint *_id = (gint*) malloc(sizeof(gint));
    *(_id) = -1;

    this->mFields[key] = _id;

    hf_register_info hfri;
    memset(&hfri, 0, sizeof hfri);

    hfri.p_id = _id;
    hfri.hfinfo.name = g_strdup_printf("%s", name);
    hfri.hfinfo.abbrev = g_strdup_printf("%s.%s", this->mKeyPrefix.c_str(), key.c_str());
    hfri.hfinfo.type = type;
    hfri.hfinfo.display = display;
    hfri.hfinfo.strings = strings;
    hfri.hfinfo.bitmask = bitmask;
    hfri.hfinfo.blurb = g_strdup_printf("%s", name);
    hfri.hfinfo.id = 0;
    hfri.hfinfo.parent = 0;
    hfri.hfinfo.ref_type = HF_REF_TYPE_NONE;
    hfri.hfinfo.bitshift = 0;
    hfri.hfinfo.same_name_next = NULL;
    hfri.hfinfo.same_name_prev = NULL;

    g_array_append_val(this->mFieldArray, hfri);

    if (subtree) {
        gint *_tid = (gint*) malloc(sizeof(gint));
        *(_tid) = -1;

        this->mSubtrees[key] = _tid;
        g_array_append_val(this->mTreeArray, _tid);
    }
}

void FieldManager::doRegister (void) {
    proto_register_field_array(this->mProto, (hf_register_info*) this->mFieldArray->data, this->mFieldArray->len);
    proto_register_subtree_array((gint* const*)this->mTreeArray->data, this->mTreeArray->len);
}

proto_tree* FieldManager::addSubtree (proto_tree *tree, std::string key, tvbuff_t *tvb, guint32 start, guint32 len) {
    proto_item *ti = proto_tree_add_item(tree, *(this->mFields[key]), tvb, start, len, FALSE);
    proto_tree *st = proto_item_add_subtree(ti, *(this->mSubtrees[key]));

    return st;
}

void FieldManager::addItem (proto_tree *tree, std::string key, tvbuff_t *tvb, guint32 start, guint32 len) {
    // TODO: move this check to a function
    if (this->mFields.find(key) != this->mFields.end())
        proto_tree_add_item(tree, *(this->mFields[key]), tvb, start, len, FALSE);
    else
        std::cerr << "Couldn't find key: " << key << std::endl;
}

proto_item* FieldManager::addBoolean (proto_tree *tree, std::string key, tvbuff_t *tvb, guint32 start, guint32 len, guint32 value) {
    // TODO: move this check to a function
    if (this->mFields.find(key) != this->mFields.end())
        return proto_tree_add_boolean(tree, *(this->mFields[key]), tvb, start, len, value);
    else
        std::cerr << "Couldn't find key: " << key << std::endl;
}
