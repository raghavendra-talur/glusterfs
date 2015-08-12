/*
  Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
  This file is part of GlusterFS.

  This file is licensed to you under your choice of the GNU Lesser
  General Public License, version 3 or any later version (LGPLv3 or
  later), or the GNU General Public License, version 2 (GPLv2), in all
  cases as published by the Free Software Foundation.
*/

#include <pthread.h>
#include "globals.h"
#include "syncop.h"
#include "event.h"
#include "timer.h"
#include "glusterfs.h"

void
__glusterfs_resource_pool_destroy ()
{

        int ret = 0;

        /* Join the syncenv_processor threads and cleanup
         * syncenv resources
         */
        syncenv_destroy (process_ctx.rp.env);

        /* Join, the poller threads.
         * TODO: In event_dispatch_destroy(), unregister all the
         * fds before destroying the poll threads?
         */
        ret = event_dispatch_destroy (process_ctx.rp.event_pool);

        gf_timer_registry_destroy();

        /* TODO: kill sigwaiter and timer wheel threads*/

        iobuf_pool_destroy (process_ctx.rp.iobuf_pool);
        mem_pool_destroy (process_ctx.rp.stub_mem_pool);
        mem_pool_destroy (process_ctx.rp.dict_pool);
        mem_pool_destroy (process_ctx.rp.dict_data_pool);
        mem_pool_destroy (process_ctx.rp.dict_pair_pool);
        mem_pool_destroy (process_ctx.rp.logbuf_pool);

        return;
}

void
__glusterfs_process_ctx_uninit ()
{
        int                  ret = -1;

        pthread_mutex_lock (&process_ctx.lock);
        {
                if (process_ctx.init != PROCESS_CTX_INIT) {
                        ret = 0;
                        goto unlock;
                }
                GF_FREE (process_ctx.cmdlinestr);
                process_ctx.cmdlinestr = NULL;

                GF_FREE (process_ctx.statedump_path);
                process_ctx.statedump_path = NULL;

                process_ctx.ib = NULL;

                __glusterfs_resource_pool_destroy ();

                FREE (process_ctx.global_xlator);
                INIT_LIST_HEAD (&process_ctx.instances);
                process_ctx.init = PROCESS_CTX_UNINIT;
        }
unlock:
        pthread_mutex_unlock (&process_ctx.lock);
}

int
glusterfs_process_ctx_unref (glusterfs_vol_ctx_t *ctx)
{
        int ret = 0;

        pthread_mutex_lock (&process_ctx.lock);
        {
                if (process_ctx.init != PROCESS_CTX_UNINIT) {
                        ret = -1;
                        goto unlock;
                }
                list_del (&ctx->list);
                if (list_empty (&process_ctx.instances)) {
                        __glusterfs_process_ctx_uninit ();
                }
        }
unlock:
        pthread_mutex_unlock (&process_ctx.lock);

        return ret;
}

int
glusterfs_process_ctx_ref (glusterfs_vol_ctx_t *ctx)
{
        int ret = 0;

        pthread_mutex_lock (&process_ctx.lock);
        {
                if (process_ctx.init != PROCESS_CTX_UNINIT) {
                        ret = -1;
                        goto unlock;
                }
                list_add_tail (&process_ctx.instances, &ctx->list);
        }
unlock:
        pthread_mutex_unlock (&process_ctx.lock);

        return ret;
}

void
glusterfs_vol_ctx_destroy (glusterfs_vol_ctx_t *ctx)
{
        glusterfs_graph_t  *trav_graph = NULL;
        glusterfs_graph_t  *tmp        = NULL;

        pthread_mutex_lock (&ctx->lock);
        {
		ctx->cleanup_started = 1;

                /* Destroy all the inode tables of all the graphs.
                 * NOTE:
                 * - inode objects should be destroyed before calling fini()
                 *   of each xlator, as fini() and forget() of the xlators
                 *   can share few common locks or data structures, calling
                 *   fini first might destroy those required by forget
                 *   ( eg: in quick-read)
                 * - The call to inode_table_destroy_all is not required when
                 *   the cleanup during graph switch is implemented to perform
                 *   inode table destroy.
                 */
		inode_table_destroy_all (ctx);

                /* Call fini() of all the xlators in the active graph
                 * NOTE:
                 * - xlator fini() should be called before destroying any of
                 *   the threads. (eg: fini() in protocol-client uses timer
                 *   thread) */
		glusterfs_graph_deactivate (ctx->active);

		gf_log_fini (ctx);

		/* For all the graphs, crawl through the xlator_t structs and free
		 * all its members except for the mem_acct member,
		 * as GF_FREE will be referencing it.
		 */
		list_for_each_entry_safe (trav_graph, tmp, &ctx->graphs, list) {
			xlator_tree_free_members (trav_graph->first);
		}

		GF_FREE (ctx->process_uuid);
		GF_FREE (ctx->cmd_args.volfile_id);

                if (ctx->pool) {
			mem_pool_destroy (ctx->pool->frame_mem_pool);
			mem_pool_destroy (ctx->pool->stack_mem_pool);
		}
		GF_FREE (ctx->pool);

		pthread_mutex_destroy (&(ctx->lock));
		pthread_mutex_destroy (&(ctx->notify_lock));
		pthread_cond_destroy (&(ctx->notify_cond));

		/* Free all the graph structs and its containing xlator_t structs
		 * from this point there should be no reference to GF_FREE/GF_CALLOC
		 * as it will try to access mem_acct and the below funtion would
		 * have freed the same.
		 */
		list_for_each_entry_safe (trav_graph, tmp, &ctx->graphs, list) {
			glusterfs_graph_destroy_residual (trav_graph);
		}
        }
        pthread_mutex_unlock (&ctx->lock);

        glusterfs_process_ctx_unref (ctx);

        GF_FREE (ctx);

        return;
}
