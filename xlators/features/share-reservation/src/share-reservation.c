/*
   Copyright (c) 2015 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#include "share-reservation.h"
#include "share-reservation-mem-types.h"

static gf_boolean_t
sr_enabled (xlator_t *this)
{
        sr_private_t           *priv = NULL;

        priv = this->private;

        return priv->sr_enabled;
}

static gf_boolean_t
sr_conflict (xlator_t *this,
                sr_entry_t *entry,
                uint32_t access_mask,
                uint32_t sr_flag)
{
        gf_msg_debug (this->name, 0, "Checking for share conflict "
                      "entry->access_mask = 0x%x, "
                      "entry->share_access = 0x%x, "
                      "access_mask = 0x%x, "
                      "share_access = 0x%x",
                      (int32_t)entry->fd->flags,
                      (int32_t)entry->sr_flag,
                      (int32_t)access_mask,
                      (int32_t)sr_flag);

    //    CHECK_MASK(1, entry->access_mask, FILE_WRITE_DATA | FILE_APPEND_DATA,
    //               share_access, FILE_SHARE_WRITE);
    //    CHECK_MASK(2, access_mask, FILE_WRITE_DATA | FILE_APPEND_DATA,
    //               entry->share_access, FILE_SHARE_WRITE);

    //    CHECK_MASK(3, entry->access_mask, FILE_READ_DATA | FILE_EXECUTE,
    //               share_access, FILE_SHARE_READ);
    //    CHECK_MASK(4, access_mask, FILE_READ_DATA | FILE_EXECUTE,
    //               entry->share_access, FILE_SHARE_READ);

        gf_msg_debug (this->name, 0, "No conflict found");
        return _gf_false;
}

int32_t
sr_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
             int32_t op_ret, int32_t op_errno, fd_t *fd, dict_t *xdata)
{
        STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd, xdata);

        return 0;
}


int32_t
sr_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
         fd_t *fd, dict_t *xdata)
{
        int32_t         op_errno        = 0;
        int             ret             = -1;


        IF_SR_DISABLED_GOTO (this, out);

out:
        STACK_WIND (frame, sr_open_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->open,
                    loc, flags, fd, xdata);

        return 0;
}

int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        ret = xlator_mem_acct_init (this, gf_sr_mt_end + 1);
        if (ret) {
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM, SR_MSG_NO_MEMORY,
                        "Failed to allocate memory for memory accounting");
        }
        return ret;
}

int32_t
init (xlator_t *this)
{
        int                     ret     = -1;
        sr_private_t           *priv    = NULL;

        if (!this->children || this->children->next) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        SR_MSG_INVALID_CONFIG, "Not configured with exactly "
                        "one child. exiting");
                goto out;
        }

        if (!this->parents) {
                gf_msg (this->name, GF_LOG_ERROR, EINVAL,
                        SR_MSG_INVALID_CONFIG,
                        "Dangling volume. check volfile");
                goto out;
        }

        priv = GF_CALLOC (1, sizeof (*priv), gf_sr_mt_private_t);
        if (!priv) {
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM, SR_MSG_NO_MEMORY,
                        "Failed to allocate memory for private data");
                goto out;
        }


        GF_OPTION_INIT ("share-reservation", priv->sr_enabled, bool, out);
        pthread_mutex_init (&priv->lock, NULL);

        this->private = priv;
        ret = 0;


out:
        if (ret) {
                GF_FREE (priv);
        }

        return ret;
}

int32_t
fini (xlator_t *this)
{
        int                     ret     = -1;
        sr_private_t           *priv    = NULL;

        priv = this->private;
        if (!priv) {
                goto out;
        }
        this->private = NULL;

        ret = 0;


out:
        GF_FREE (priv);
        return ret;
}

static int
sr_forget (xlator_t *this, inode_t *inode)
{
        return 0;
}

static int
sr_release (xlator_t *this, fd_t *fd)
{
        return 0;
}

struct xlator_fops fops = {
        .open           = sr_open,
};

struct xlator_cbks cbks = {
        .forget         = sr_forget,
        .release        = sr_release,
};

struct volume_options options[] = {
        { .key  = {"share-reservation"},
          .type = GF_OPTION_TYPE_BOOL,
          .default_value = "off",
          .description = "When enabled, enforces share-reservation"
        },
        { .key  = {NULL} },
};
