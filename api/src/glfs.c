/*
  Copyright (c) 2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/


/*
  TODO:
  - set proper pid/lk_owner to call frames (currently buried in syncop)
  - fix logging.c/h to store logfp and loglevel in glusterfs_ctx_t and
    reach it via THIS.
  - update syncop functions to accept/return xdata. ???
  - protocol/client to reconnect immediately after portmap disconnect.
  - handle SEEK_END failure in _lseek()
  - handle umask (per filesystem?)
  - make itables LRU based
  - 0-copy for readv/writev
  - reconcile the open/creat mess
*/

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include "glusterfs.h"
#include "logging.h"
#include "stack.h"
#include "event.h"
#include "glfs-mem-types.h"
#include "common-utils.h"
#include "syncop.h"
#include "call-stub.h"
#include "gfapi-messages.h"

#include "glfs.h"
#include "glfs-internal.h"
#include "hashfn.h"
#include "rpc-clnt.h"
#include "statedump.h"

static gf_boolean_t
vol_assigned (cmd_args_t *args)
{
	return args->volfile || args->volfile_server;
}

static int
create_master (struct glfs *fs)
{
	int		 ret = 0;
	xlator_t	*master = NULL;

	master = GF_CALLOC (1, sizeof (*master),
			    glfs_mt_xlator_t);
	if (!master)
		goto err;

	master->name = gf_strdup ("gfapi");
	if (!master->name)
		goto err;

	if (xlator_set_type (master, "mount/api") == -1) {
		gf_msg ("glfs", GF_LOG_ERROR, 0,
                        API_MSG_MASTER_XLATOR_INIT_FAILED, "master xlator "
                        "for %s initialization failed", fs->volname);
		goto err;
	}

	master->ctx	 = fs->ctx;
	master->private	 = fs;
	master->options	 = get_new_dict ();
	if (!master->options)
		goto err;


	ret = xlator_init (master);
	if (ret) {
		gf_msg ("glfs", GF_LOG_ERROR, 0,
                        API_MSG_GFAPI_XLATOR_INIT_FAILED,
			"failed to initialize gfapi translator");
		goto err;
	}

	fs->ctx->master = master;
	THIS = master;

	return 0;

err:
	if (master) {
		xlator_destroy (master);
	}

	return -1;
}


static FILE *
get_volfp (struct glfs *fs)
{
	cmd_args_t  *cmd_args = NULL;
	FILE	    *specfp = NULL;

	cmd_args = &fs->ctx->cmd_args;

	if ((specfp = fopen (cmd_args->volfile, "r")) == NULL) {
		gf_msg ("glfs", GF_LOG_ERROR, errno,
                        API_MSG_VOLFILE_OPEN_FAILED,
			"volume file %s open failed: %s",
			cmd_args->volfile,
			strerror (errno));
		return NULL;
	}

	gf_msg_debug ("glfs", 0, "loading volume file %s", cmd_args->volfile);

	return specfp;
}


int
glfs_volumes_init (struct glfs *fs)
{
	FILE		   *fp = NULL;
	cmd_args_t	   *cmd_args = NULL;
	int		    ret = 0;

	cmd_args = &fs->ctx->cmd_args;

	if (!vol_assigned (cmd_args))
		return -1;

	if (cmd_args->volfile_server) {
		ret = glfs_mgmt_init (fs);
		goto out;
	}

	fp = get_volfp (fs);

	if (!fp) {
		gf_msg ("glfs", GF_LOG_ERROR, ENOENT,
                        API_MSG_VOL_SPEC_FILE_ERROR,
			"Cannot reach volume specification file");
		ret = -1;
		goto out;
	}

	ret = glfs_process_volfp (fs, fp);
	if (ret)
		goto out;

out:
	return ret;
}


///////////////////////////////////////////////////////////////////////////////


int
pub_glfs_set_xlator_option (struct glfs *fs, const char *xlator,
                            const char *key, const char *value)
{
	xlator_cmdline_option_t *option = NULL;

        DECLARE_OLD_THIS;
        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

	option = GF_CALLOC (1, sizeof (*option),
			    glfs_mt_xlator_cmdline_option_t);
	if (!option)
		goto enomem;

	INIT_LIST_HEAD (&option->cmd_args);

	option->volume = gf_strdup (xlator);
	if (!option->volume)
		goto enomem;
	option->key = gf_strdup (key);
	if (!option->key)
		goto enomem;
	option->value = gf_strdup (value);
	if (!option->value)
		goto enomem;

	list_add (&option->cmd_args, &fs->ctx->cmd_args.xlator_options);

        __GLFS_EXIT_FS;

	return 0;
enomem:
	errno = ENOMEM;

	if (!option) {
                __GLFS_EXIT_FS;
		return -1;
        }

	GF_FREE (option->volume);
	GF_FREE (option->key);
	GF_FREE (option->value);
	GF_FREE (option);

        __GLFS_EXIT_FS;

invalid_fs:
	return -1;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_set_xlator_option, 3.4.0);


int
pub_glfs_unset_volfile_server (struct glfs *fs, const char *transport,
                               const char *host, const int port)
{
        cmd_args_t       *cmd_args = NULL;
        server_cmdline_t *server = NULL;
        server_cmdline_t *tmp = NULL;
        char             *transport_val = NULL;
        int               port_val = 0;
        int               ret = -1;

        if (!fs || !host) {
                errno = EINVAL;
                return ret;
        }

        DECLARE_OLD_THIS;
        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

        cmd_args = &fs->ctx->cmd_args;

        if (transport) {
                transport_val = gf_strdup (transport);
        } else {
                transport_val = gf_strdup (GF_DEFAULT_VOLFILE_TRANSPORT);
        }

        if (!transport_val) {
                errno = ENOMEM;
                goto out;
        }

        if (port) {
                port_val = port;
        } else {
                port_val = GF_DEFAULT_BASE_PORT;
        }

        list_for_each_entry_safe (server, tmp,
                                  &cmd_args->curr_server->list,
                                  list) {
                if ((!strcmp(server->volfile_server, host) &&
                     !strcmp(server->transport, transport_val) &&
                     (server->port == port_val))) {
                        list_del (&server->list);
                        ret = 0;
                        goto out;
                }
        }

out:
        GF_FREE (transport_val);
        __GLFS_EXIT_FS;

invalid_fs:
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_unset_volfile_server, 3.5.1);


int
pub_glfs_set_volfile_server (struct glfs *fs, const char *transport,
                             const char *host, int port)
{
        cmd_args_t            *cmd_args = NULL;
        server_cmdline_t      *server = NULL;
        server_cmdline_t      *tmp = NULL;
        int                    ret = -1;

        if (!fs || !host) {
                errno = EINVAL;
                return ret;
        }

        DECLARE_OLD_THIS;
        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

        cmd_args = &fs->ctx->cmd_args;

        cmd_args->max_connect_attempts = 1;

        server = GF_CALLOC (1, sizeof (server_cmdline_t),
                            glfs_mt_server_cmdline_t);

        if (!server) {
                errno = ENOMEM;
                goto out;
        }

        INIT_LIST_HEAD (&server->list);

        server->volfile_server = gf_strdup (host);
        if (!server->volfile_server) {
                errno = ENOMEM;
                goto out;
        }

        if (transport) {
                server->transport = gf_strdup (transport);
        } else {
                server->transport = gf_strdup (GF_DEFAULT_VOLFILE_TRANSPORT);
        }

        if (!server->transport) {
                errno = ENOMEM;
                goto out;
        }

        if (port) {
                server->port = port;
        } else {
                server->port = GF_DEFAULT_BASE_PORT;
        }

        if (!cmd_args->volfile_server) {
                cmd_args->volfile_server = server->volfile_server;
                cmd_args->volfile_server_transport = server->transport;
                cmd_args->volfile_server_port = server->port;
                cmd_args->curr_server = server;
        }

        list_for_each_entry(tmp, &cmd_args->volfile_servers, list) {
                if ((!strcmp(tmp->volfile_server, server->volfile_server) &&
                     !strcmp(tmp->transport, server->transport) &&
                     (tmp->port == server->port))) {
                        errno = EEXIST;
                        ret = -1;
                        goto out;
                }
        }

        list_add_tail (&server->list, &cmd_args->volfile_servers);

        ret = 0;
out:
        if (ret == -1) {
                if (server) {
                        GF_FREE (server->volfile_server);
                        GF_FREE (server->transport);
                        GF_FREE (server);
                }
        }

        __GLFS_EXIT_FS;

invalid_fs:
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_set_volfile_server, 3.4.0);


int
pub_glfs_setfsuid (uid_t fsuid)
{
         /* TODO:
         * - Set the THIS and restore it appropriately
         */
	return syncopctx_setfsuid (&fsuid);
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_setfsuid, 3.4.2);


int
pub_glfs_setfsgid (gid_t fsgid)
{
         /* TODO:
         * - Set the THIS and restore it appropriately
         */
	return syncopctx_setfsgid (&fsgid);
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_setfsgid, 3.4.2);


int
pub_glfs_setfsgroups (size_t size, const gid_t *list)
{
         /* TODO:
         * - Set the THIS and restore it appropriately
         */
	return syncopctx_setfsgroups(size, list);
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_setfsgroups, 3.4.2);


struct glfs *
pub_glfs_from_glfd (struct glfs_fd *glfd)
{
	return glfd->fs;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_from_glfd, 3.4.0);

void
glfs_fd_destroy (void *data)
{
        struct glfs_fd  *glfd = NULL;

        if (!data)
                return;

        glfd = (struct glfs_fd *)data;

        glfs_lock (glfd->fs);
        {
                list_del_init (&glfd->openfds);
        }
        glfs_unlock (glfd->fs);

        if (glfd->fd) {
                fd_unref (glfd->fd);
                glfd->fd = NULL;
        }

        GF_FREE (glfd->readdirbuf);

        GF_FREE (glfd);
}


struct glfs_fd *
glfs_fd_new (struct glfs *fs)
{
	struct glfs_fd  *glfd = NULL;

	glfd = GF_CALLOC (1, sizeof (*glfd), glfs_mt_glfs_fd_t);
	if (!glfd)
		return NULL;

	glfd->fs = fs;

	INIT_LIST_HEAD (&glfd->openfds);

        GF_REF_INIT (glfd, glfs_fd_destroy);

	return glfd;
}


void
glfs_fd_bind (struct glfs_fd *glfd)
{
	struct glfs *fs = NULL;

	fs = glfd->fs;

	glfs_lock (fs);
	{
		list_add_tail (&glfd->openfds, &fs->openfds);
	}
	glfs_unlock (fs);
}


static void *
glfs_poller ()
{
	event_dispatch (process_ctx.rp.event_pool);

	return NULL;
}

static glusterfs_vol_ctx_t *
glusterfs_new_vol_ctx (glfs_t *fs, const char *volname)
{
        glusterfs_vol_ctx_t *ctx      = NULL;
        int                  ret      = -1;

        ctx = GF_CALLOC (1, sizeof (glusterfs_vol_ctx_t), gf_common_mt_vol_ctx_t);
        if (!ctx) {
                errno = ENOMEM;
                goto out;
        }

        pthread_mutex_init (&(ctx->lock), NULL);

        INIT_LIST_HEAD (&ctx->cmd_args.xlator_options);
        INIT_LIST_HEAD (&ctx->cmd_args.volfile_servers);
        INIT_LIST_HEAD (&ctx->graphs);
        INIT_LIST_HEAD (&ctx->list);

        THIS = ctx->init_xlator;
        THIS->ctx = ctx;

        ctx->process_uuid = generate_glusterfs_ctx_id ();
        if (!ctx->process_uuid) {
                goto out;
        }

        ctx->pool = GF_CALLOC (1, sizeof (call_pool_t), gf_common_mt_call_pool_t);
        if (!ctx->pool) {
                goto out;
        }

        INIT_LIST_HEAD (&(ctx->pool)->all_frames);
        LOCK_INIT (&(ctx->pool->lock));

        /* frame_mem_pool size 112 * 4k */
        ctx->pool->frame_mem_pool = mem_pool_new (call_frame_t, 4096);
        if (!ctx->pool->frame_mem_pool) {
                goto out;
        }
        /* stack_mem_pool size 256 * 1024 */
        ctx->pool->stack_mem_pool = mem_pool_new (call_stack_t, 1024);
        if (!ctx->pool->stack_mem_pool) {
                goto out;
        }

        ret = glfs_set_logging (fs, "/dev/null", 0);
        if (ret)
                goto out;

        fs->ctx->cmd_args.volfile_id = gf_strdup (volname);
        if (!(fs->ctx->cmd_args.volfile_id))
                goto out;

        ret = glusterfs_process_ctx_ref (ctx);
        if (ret < 0)
                goto out;

        ret = 0;
out:
        if (ret < 0) {
                if (ctx->pool) {
                        mem_pool_destroy (ctx->pool->frame_mem_pool);
                        mem_pool_destroy (ctx->pool->stack_mem_pool);
                        GF_FREE (ctx->pool);
                }
                GF_FREE (ctx->process_uuid);
                GF_FREE (ctx->cmd_args.volfile_id);
                GF_FREE (ctx);
                /*log_fini()?*/
                ctx = NULL;
        }

        return ctx;
}

static int
__glusterfs_resource_pool_init ()
{
        int    ret = -1;

        process_ctx.rp.page_size  = 128 * GF_UNIT_KB;

        process_ctx.rp.iobuf_pool = iobuf_pool_new ();
        if (!process_ctx.rp.iobuf_pool) {
                goto out;
        }

        process_ctx.rp.event_pool = event_pool_new (DEFAULT_EVENT_POOL_SIZE,
                                                 STARTING_EVENT_THREADS);
        if (!process_ctx.rp.event_pool) {
                goto out;
        }

        process_ctx.rp.env = syncenv_new (0, 0, 0);
        if (!process_ctx.rp.env) {
                goto out;
        }

        process_ctx.rp.stub_mem_pool = mem_pool_new (call_stub_t, 1024);
        if (!process_ctx.rp.stub_mem_pool) {
                goto out;
        }

        process_ctx.rp.dict_pool = mem_pool_new (dict_t, GF_MEMPOOL_COUNT_OF_DICT_T);
        if (!process_ctx.rp.dict_pool)
                goto out;

        process_ctx.rp.dict_pair_pool = mem_pool_new (data_pair_t,
                                            GF_MEMPOOL_COUNT_OF_DATA_PAIR_T);
        if (!process_ctx.rp.dict_pair_pool)
                goto out;

        process_ctx.rp.dict_data_pool = mem_pool_new (data_t, GF_MEMPOOL_COUNT_OF_DATA_T);
        if (!process_ctx.rp.dict_data_pool)
                goto out;

        process_ctx.rp.logbuf_pool = mem_pool_new (log_buf_t,
                                         GF_MEMPOOL_COUNT_OF_LRU_BUF_T);
        if (!process_ctx.rp.logbuf_pool)
                goto out;

        if (gf_timer_registry_init() == NULL)
                goto out;

        ret = gf_thread_create (&process_ctx.rp.poller, NULL, glfs_poller, NULL);
        if (ret)
                return ret;

        ret = 0;
out:
        return ret;
}


static int
glusterfs_init_process_ctx ()
{
        int                  ret = -1;

        pthread_mutex_lock (&process_ctx.lock);
        {
                if (process_ctx.init != PROCESS_CTX_UNINIT) {
                        ret = 0;
                        goto err;
                }

                process_ctx.mem_acct_enable = gf_global_mem_acct_enable_get();

                ret = glusterfs_globals_init ();
                if (ret)
                        goto err;

                process_ctx.global_xlator = CALLOC (1, sizeof (xlator_t));
                if (!process_ctx.global_xlator)
                        goto err;

                THIS = process_ctx.global_xlator;
                THIS->ctx = NULL;

                ret = xlator_mem_acct_init (THIS, gf_common_mt_end);
                if (ret != 0)
                        goto err;

                INIT_LIST_HEAD (&process_ctx.instances);
                gf_proc_dump_init ();

                ret = __glusterfs_resource_pool_init ();
                if (ret < 0)
                        goto err;

                process_ctx.init = PROCESS_CTX_INIT;
                ret = 0;

err:
                if (ret < 0)
                        __glusterfs_process_ctx_uninit ();
        }
        pthread_mutex_unlock (&process_ctx.lock);

        return ret;
}

static struct glfs *
glfs_new_fs (const char *volname)
{
        struct glfs     *fs             = NULL;

        fs = CALLOC (1, sizeof (*fs));
        if (!fs)
                return NULL;

        INIT_LIST_HEAD (&fs->openfds);
        INIT_LIST_HEAD (&fs->upcall_list);

        PTHREAD_MUTEX_INIT (&fs->mutex, NULL, fs->pthread_flags,
                            GLFS_INIT_MUTEX, err);

        PTHREAD_COND_INIT (&fs->cond, NULL, fs->pthread_flags,
                           GLFS_INIT_COND, err);

        PTHREAD_COND_INIT (&fs->child_down_cond, NULL, fs->pthread_flags,
                           GLFS_INIT_COND_CHILD, err);

        PTHREAD_MUTEX_INIT (&fs->upcall_list_mutex, NULL, fs->pthread_flags,
                            GLFS_INIT_MUTEX_UPCALL, err);

        fs->volname = strdup (volname);
        if (!fs->volname)
                goto err;

        fs->pin_refcnt = 0;

        return fs;

err:
        glfs_free_from_ctx (fs);
        return NULL;
}

struct glfs *
pub_glfs_new (const char *volname)
{
	struct glfs         *fs             = NULL;
	int                  ret            = -1;
	glusterfs_vol_ctx_t *ctx            = NULL;
        xlator_t            *old_THIS       = NULL;

        if (!volname) {
                errno = EINVAL;
                return NULL;
        }

        fs = glfs_new_fs (volname);
        if (!fs)
                return NULL;

        ret = glusterfs_init_process_ctx ();
        if (ret)
                return NULL;

        old_THIS = THIS;

        ctx = glusterfs_new_vol_ctx (fs, volname);
        if (!ctx)
                return NULL;

        fs->ctx = ctx;

        if (old_THIS)
                THIS = old_THIS;

        return fs;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_new, 3.4.0);


struct glfs *
priv_glfs_new_from_ctx (glusterfs_vol_ctx_t *ctx)
{
        struct glfs    *fs = NULL;

        if (!ctx)
                goto out;

        fs = glfs_new_fs ("");
        if (!fs)
                goto out;

        fs->ctx = ctx;

out:
        return fs;
}

GFAPI_SYMVER_PRIVATE_DEFAULT(glfs_new_from_ctx, 3.7.0);


void
priv_glfs_free_from_ctx (struct glfs *fs)
{
        upcall_entry       *u_list   = NULL;
        upcall_entry       *tmp      = NULL;

        if (!fs)
                return;

        /* cleanup upcall structures */
        list_for_each_entry_safe (u_list, tmp,
                                  &fs->upcall_list,
                                  upcall_list) {
                list_del_init (&u_list->upcall_list);
                GF_FREE (u_list->upcall_data.data);
                GF_FREE (u_list);
        }

        PTHREAD_MUTEX_DESTROY (&fs->mutex, fs->pthread_flags, GLFS_INIT_MUTEX);

        PTHREAD_COND_DESTROY (&fs->cond, fs->pthread_flags, GLFS_INIT_COND);

        PTHREAD_COND_DESTROY (&fs->child_down_cond, fs->pthread_flags,
                              GLFS_INIT_COND_CHILD);

        PTHREAD_MUTEX_DESTROY (&fs->upcall_list_mutex, fs->pthread_flags,
                               GLFS_INIT_MUTEX_UPCALL);

        FREE (fs->volname);

        FREE (fs);
}

GFAPI_SYMVER_PRIVATE_DEFAULT(glfs_free_from_ctx, 3.7.0);


int
pub_glfs_set_volfile (struct glfs *fs, const char *volfile)
{
	cmd_args_t  *cmd_args = NULL;

	cmd_args = &fs->ctx->cmd_args;

	if (vol_assigned (cmd_args))
		return -1;

	cmd_args->volfile = gf_strdup (volfile);
        if (!cmd_args->volfile)
                return -1;
	return 0;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_set_volfile, 3.4.0);


int
pub_glfs_set_logging (struct glfs *fs, const char *logfile, int loglevel)
{
        int  ret = -1;
        char *tmplog = NULL;

        DECLARE_OLD_THIS;
        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

        if (!logfile) {
                ret = gf_set_log_file_path (&fs->ctx->cmd_args);
                if (ret)
                        goto out;
                tmplog = fs->ctx->cmd_args.log_file;
        } else {
                tmplog = (char *)logfile;
        }

        /* finish log set parameters before init */
        if (loglevel >= 0)
                gf_log_set_loglevel (loglevel);

        ret = gf_log_init (fs->ctx, tmplog, NULL);
        if (ret)
                goto out;

        ret = gf_log_inject_timer_event (fs->ctx);
        if (ret)
                goto out;

out:
        __GLFS_EXIT_FS;

invalid_fs:
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_set_logging, 3.4.0);


int
glfs_init_wait (struct glfs *fs)
{
	int   ret = -1;

	/* Always a top-down call, use glfs_lock() */
	glfs_lock (fs);
	{
		while (!fs->init)
			pthread_cond_wait (&fs->cond,
					   &fs->mutex);
		ret = fs->ret;
		errno = fs->err;
	}
	glfs_unlock (fs);

	return ret;
}


void
priv_glfs_init_done (struct glfs *fs, int ret)
{
	glfs_init_cbk init_cbk;

	if (!fs) {
		gf_msg ("glfs", GF_LOG_ERROR, EINVAL, API_MSG_GLFS_FSOBJ_NULL,
			"fs is NULL");
		goto out;
	}

	init_cbk = fs->init_cbk;

	/* Always a bottom-up call, use mutex_lock() */
	pthread_mutex_lock (&fs->mutex);
	{
		fs->init = 1;
		fs->ret = ret;
		fs->err = errno;

		if (!init_cbk)
			pthread_cond_broadcast (&fs->cond);
	}
	pthread_mutex_unlock (&fs->mutex);

	if (init_cbk)
		init_cbk (fs, ret);
out:
	return;
}

GFAPI_SYMVER_PRIVATE_DEFAULT(glfs_init_done, 3.4.0);


int
glfs_init_common (struct glfs *fs)
{
	int  ret = -1;

	ret = create_master (fs);
	if (ret)
		return ret;

	ret = gf_thread_create (&fs->poller, NULL, glfs_poller, fs);
	if (ret)
		return ret;

	ret = glfs_volumes_init (fs);
	if (ret)
		return ret;

	fs->dev_id = gf_dm_hashfn (fs->volname, strlen (fs->volname));
	return ret;
}


int
glfs_init_async (struct glfs *fs, glfs_init_cbk cbk)
{
	int  ret = -1;

	if (!fs || !fs->ctx) {
		gf_msg ("glfs", GF_LOG_ERROR, EINVAL, API_MSG_INVALID_ENTRY,
			"fs is not properly initialized.");
		errno = EINVAL;
		return ret;
	}

	fs->init_cbk = cbk;

	ret = glfs_init_common (fs);

	return ret;
}


int
pub_glfs_init (struct glfs *fs)
{
	int  ret = -1;

        DECLARE_OLD_THIS;

	if (!fs || !fs->ctx) {
		gf_msg ("glfs", GF_LOG_ERROR, EINVAL, API_MSG_INVALID_ENTRY,
			"fs is not properly initialized.");
		errno = EINVAL;
		return ret;
	}

        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

	ret = glfs_init_common (fs);
	if (ret)
		goto out;

	ret = glfs_init_wait (fs);
out:
        __GLFS_EXIT_FS;

        /* Set the initial current working directory to "/" */
        if (ret >= 0) {
                ret = glfs_chdir (fs, "/");
        }

invalid_fs:
	return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_init, 3.4.0);

int
pub_glfs_fini (struct glfs *fs)
{
        int                  ret = -1;
        int                  countdown = 100;
        xlator_t            *subvol = NULL;
        glusterfs_vol_ctx_t *ctx = NULL;
        glusterfs_graph_t   *graph = NULL;
        call_pool_t         *call_pool = NULL;
        int                  fs_init = 0;
        int                  err = -1;

        DECLARE_OLD_THIS;

        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

        ctx = fs->ctx;
        if (!ctx) {
                goto free_fs;
        }

        if (ctx->mgmt) {
                rpc_clnt_disable (ctx->mgmt);
                ctx->mgmt = NULL;
        }

        call_pool = fs->ctx->pool;

        while (countdown--) {
                /* give some time for background frames to finish */
                pthread_mutex_lock (&fs->mutex);
                {
                        /* Do we need to increase countdown? */
                        if ((!call_pool->cnt) && (!fs->pin_refcnt)) {
                                gf_msg_trace ("glfs", 0,
                                        "call_pool_cnt - %ld,"
                                        "pin_refcnt - %d",
                                        call_pool->cnt, fs->pin_refcnt);

                                ctx->cleanup_started = 1;
                                pthread_mutex_unlock (&fs->mutex);
                                break;
                        }
                }
                pthread_mutex_unlock (&fs->mutex);
                usleep (100000);
        }

        /* leaked frames may exist, we ignore */

        /*We deem glfs_fini as successful if there are no pending frames in the call
         *pool*/
        ret = (call_pool->cnt == 0)? 0: -1;

        pthread_mutex_lock (&fs->mutex);
        {
                fs_init = fs->init;
        }
        pthread_mutex_unlock (&fs->mutex);

        if (fs_init != 0) {
                subvol = glfs_active_subvol (fs);
                if (subvol) {
                        /* PARENT_DOWN within glfs_subvol_done() is issued
                           only on graph switch (new graph should activiate
                           and decrement the extra @winds count taken in
                           glfs_graph_setup()

                           Since we are explicitly destroying,
                           PARENT_DOWN is necessary
                        */
                        xlator_notify (subvol, GF_EVENT_PARENT_DOWN, subvol, 0);
                        /* Here we wait for GF_EVENT_CHILD_DOWN before exiting,
                           in case of asynchrnous cleanup
                        */
                        graph = subvol->graph;
                        err = pthread_mutex_lock (&fs->mutex);
                        if (err != 0) {
                                gf_msg ("glfs", GF_LOG_ERROR, err,
                                        API_MSG_FSMUTEX_LOCK_FAILED,
                                        "pthread lock on glfs mutex, "
                                        "returned error: (%s)", strerror (err));
                                goto fail;
                        }
                        /* check and wait for CHILD_DOWN for active subvol*/
                        {
                                while (graph->used) {
                                        err = pthread_cond_wait (&fs->child_down_cond,
                                                                 &fs->mutex);
                                        if (err != 0)
                                                gf_msg ("glfs", GF_LOG_INFO, err,
                                                        API_MSG_COND_WAIT_FAILED,
                                                        "%s cond wait failed %s",
                                                        subvol->name,
                                                        strerror (err));
                                }
                        }

                        err = pthread_mutex_unlock (&fs->mutex);
                        if (err != 0) {
                                gf_msg ("glfs", GF_LOG_ERROR, err,
                                        API_MSG_FSMUTEX_UNLOCK_FAILED,
                                        "pthread unlock on glfs mutex, "
                                        "returned error: (%s)", strerror (err));
                                goto fail;
                        }
                }
                glfs_subvol_done (fs, subvol);
        }

        /* Destroy the context and the global pools */
        glusterfs_vol_ctx_destroy (ctx);

free_fs:
        glfs_free_from_ctx (fs);

fail:
        if (!ret)
                ret = err;

        __GLFS_EXIT_FS;

invalid_fs:
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_fini, 3.4.0);


ssize_t
pub_glfs_get_volfile (struct glfs *fs, void *buf, size_t len)
{
        ssize_t         res = -1;

        DECLARE_OLD_THIS;
        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

        glfs_lock(fs);
        if (len >= fs->oldvollen) {
                gf_msg_trace ("glfs", 0, "copying %zu to %p", len, buf);
                memcpy(buf,fs->oldvolfile,len);
                res = len;
        }
        else {
                res = len - fs->oldvollen;
                gf_msg_trace ("glfs", 0, "buffer is %zd too short", -res);
        }
        glfs_unlock(fs);

        __GLFS_EXIT_FS;

invalid_fs:
        return res;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_get_volfile, 3.6.0);

int
pub_glfs_ipc_xd (struct glfs *fs, int opcode, dict_t *xd_in, dict_t **xd_out)
{
	xlator_t        *subvol = NULL;
        int             ret = -1;

	DECLARE_OLD_THIS;
        __GLFS_ENTRY_VALIDATE_FS (fs, invalid_fs);

	subvol = glfs_active_subvol (fs);
	if (!subvol) {
		ret = -1;
		errno = EIO;
		goto out;
	}

	ret = syncop_ipc (subvol, opcode, xd_in, xd_out);
        DECODE_SYNCOP_ERR (ret);

out:
        glfs_subvol_done (fs, subvol);
        __GLFS_EXIT_FS;

invalid_fs:
        return ret;
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_ipc_xd, 4.0.0);

int
pub_glfs_ipc (struct glfs *fs, int opcode)
{
        return pub_glfs_ipc_xd (fs, opcode, NULL, NULL);
}

GFAPI_SYMVER_PUBLIC_DEFAULT(glfs_ipc, 3.7.0);
