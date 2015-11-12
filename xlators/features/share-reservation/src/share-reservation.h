/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef __SR_H__
#define __SR_H__

#include "glusterfs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "defaults.h"
#include "share-reservation-messages.h"
#include "share-reservation-mem-types.h"




struct _sr_private {
        gf_boolean_t sr_enabled;
        pthread_mutex_t lock;
};
typedef struct _sr_private sr_private_t;

struct _sr_entry {
        struct list_head        sr_entry_list;
        fd_t                    *fd;
        int32_t                 access_mask;
        int32_t                 sr_flag;
};
typedef struct _sr_entry sr_entry_t;

struct _sr_inode_ctx {
        struct list_head        sr_entry_list;
        uint64_t                sr_count;
        uint64_t                fd_count;
        inode_t                 *inode;
        pthread_mutex_t         lock;
};
typedef struct _sr_inode_ctx sr_inode_ctx_t;

static gf_boolean_t
sr_enabled (xlator_t *this);

static gf_boolean_t
sr_conflict (xlator_t *this,
                sr_entry_t *entry,
                uint32_t access_mask,
                uint32_t sr_flag);


#define IF_SR_DISABLED_GOTO(this, label) do {          \
        if (!sr_enabled (this))                         \
                goto label;                             \
} while(0)


#define CHECK_MASK(num, am, right, sa, share) do {     \
        if (((am) & (right)) && !((sa) & (share)))      \
                return _gf_true;                        \
} while(0)

#endif /* __SR_H__ */
