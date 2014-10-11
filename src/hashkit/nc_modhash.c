/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_hashkit.h>

#define MODULA_POINTS_PER_SERVER    1


/* update continuum
	FIXME: add mutex
*/
rstatus_t
modhash_update(struct server_pool *pool)
{
    uint32_t nserver;             /* # server - live and dead */
    uint32_t nlive_server;        /* # live server */
    uint32_t pointer_per_server;  /* pointers per server proportional to weight */
    uint32_t pointer_counter;     /* # pointers on continuum */
    uint32_t points_per_server;   /* points per server */
    uint32_t continuum_index;     /* continuum index */
    uint32_t continuum_addition;  /* extra space in the continuum */
    uint32_t server_index;        /* server index */
    uint32_t total_weight;        /* total live server weight */
    int64_t now;                  /* current timestamp in usec */

    uint32_t pointer_counter_status2 ; /* #pointers on continuum of transfer status */
    uint32_t pool_transfer_status = 0;
    uint32_t pool_old_status ;
    bool first_init = false;       /* is first_init ?*/
    pool_old_status =  pool->status;

//    bool    keys_flag[MODHASH_TOTAL_KEY];
 //   memset(keys_flag, 0, sizeof(keys_flag));

    now = nc_usec_now();
    if (now < 0) {
        return NC_ERROR;
    }
    nserver = array_n(&pool->server);

	//int old_server_idx = -1;
	for (server_index = 0; server_index < nserver; server_index++) {
		struct server *s = (struct server *) array_get(&pool->server, server_index);
		log_debug(LOG_VERB, "modhash_update server %s", s->pname.data);
	}


    if(NC_OK != server_check_hash_keys(pool) ){
       log_error("there may be some error in the config file.");
       return NC_ERROR;
    }

    nserver = array_n(&pool->server);
   // log_debug(LOG_VERB,"found n servers in modhash_update: %ld . keys_flag: %d\n",nserver, sizeof(keys_flag));

    nlive_server = 0;
    total_weight = 0;
    pool->next_rebuild = 0LL;

    for (server_index = 0; server_index < nserver; server_index++) {
        struct server *server = array_get(&pool->server, server_index);

        if (pool->auto_eject_hosts) {
            if (server->next_retry <= now) {
                server->next_retry = 0LL;
            } else if (pool->next_rebuild == 0LL ||
                       server->next_retry < pool->next_rebuild) {
                pool->next_rebuild = server->next_retry;
            }
        } 

        /* next retry time,we rebuild. for modhash ,wo donot auto_eject_hosts */
        nlive_server++;

        /* take no account the weight */
        /* ASSERT(server->weight > 0); */

        /* count weight only for live servers */
        if (!pool->auto_eject_hosts || server->next_retry <= now) {
            total_weight += server->weight;
        }
    }

    pool->nlive_server = nlive_server;

    if (nlive_server == 0) {
        ASSERT(pool->continuum != NULL);
        ASSERT(pool->ncontinuum != 0);

        log_debug(LOG_DEBUG, "no live servers for pool %"PRIu32" '%.*s'",
                  pool->idx, pool->name.len, pool->name.data);

        return NC_OK;
    }
    log_debug(LOG_DEBUG, "%"PRIu32" of %"PRIu32" servers are live for pool "
              "%"PRIu32" '%.*s'", nlive_server, nserver, pool->idx,
              pool->name.len, pool->name.data);

    continuum_addition = 0;
    points_per_server = MODULA_POINTS_PER_SERVER;

    /*
     * Allocate the continuum for the pool, the first time. 
     * infact we would never add new server here, because our hash is hard code to MODHASH_TOTAL_KEY.
     */
    if ( pool->nserver_continuum != MODHASH_TOTAL_KEY) {
        struct continuum *continuum;
        uint32_t nserver_continuum = MODHASH_TOTAL_KEY;
        uint32_t ncontinuum = nserver_continuum *  MODULA_POINTS_PER_SERVER;

        continuum = nc_realloc(pool->continuum, sizeof(*continuum) * ncontinuum);
        if (continuum == NULL) {
            return NC_ENOMEM;
        }

        pool->continuum = continuum;
        pool->nserver_continuum = nserver_continuum;
        /* pool->ncontinuum is initialized later as it could be <= ncontinuum */
        first_init = true;
    }

    /* update the continuum with the servers that are live */
    continuum_index = 0;
    pointer_counter = 0;
    for (server_index = 0; server_index < nserver; server_index++) {
    	pointer_per_server = 1;
        struct server *server = array_get(&pool->server, server_index);
        int idx;

        if (server->status != 1 ) {
        	continue;
        }

		 for (idx = server->seg_start; idx <= server->seg_end; idx++) {
			pool->continuum[idx].index = server_index;
			pool->continuum[idx].value = 0;
			pool->continuum[idx].status = CONTINUUM_STATUS_NOTRANS;
			//pool->continuum[idx].newindex = 0; //new index

			pointer_counter += pointer_per_server;
		 }

		 pool_transfer_status = 1;
    }

    pool->ncontinuum = pointer_counter;

    /*
     * update the continuum with the servers which status is 2
     */
    pointer_counter_status2 = 0;
    for (server_index = 0; server_index < nserver; server_index++) {
    	pointer_per_server = 1;
        struct server *server = array_get(&pool->server, server_index);
        int idx;

         if (server->status != 2 ) {
           	continue;
         }

   		 for (idx = server->seg_start; idx <= server->seg_end; idx++) {
   			pool->continuum[idx].newindex = server_index;
   			pool->continuum[idx].status = CONTINUUM_STATUS_TRANSING;
   			pointer_counter_status2 += pointer_per_server;
   		 }
   		pool_transfer_status = 2;
    }

	pool->ntrans_continuum = pointer_counter_status2;
	pool->status = pool_transfer_status;

	if (pool_old_status != pool_transfer_status) {
		log_error("pool %.*s status changed from %d to %d", pool->name.len, pool->name.data, pool_old_status, pool_transfer_status);
	}

    log_debug(LOG_VERB, "updated pool %"PRIu32" '%.*s' with %"PRIu32" of "
              "%"PRIu32" servers live in %"PRIu32" slots and %"PRIu32" "
              "active points in %"PRIu32" slots poolstatus %d status-2-slots %d", pool->idx,
              pool->name.len, pool->name.data, nlive_server, nserver,
              pool->nserver_continuum, pool->ncontinuum,
              (pool->nserver_continuum + continuum_addition) * points_per_server, pool->status, pointer_counter_status2);


    return NC_OK;
}


uint32_t
modhash_dispatch(struct continuum *continuum, uint32_t ncontinuum, uint32_t hash)
{
    struct continuum *c;

    ASSERT(continuum != NULL);
    ASSERT(ncontinuum != 0);

    c = continuum + hash % ncontinuum;
    ASSERT( c->status > 0  );
    log_debug(LOG_VERB, "choose No. %d continuum,hash:%u ,ncontinuum: %u \n",hash%ncontinuum,hash,ncontinuum);

    return (c->status == CONTINUUM_STATUS_TRANSED ) ? c->newindex : c->index;
}

uint32_t
modhash_dispatch_newserver(struct continuum *continuum, uint32_t ncontinuum, uint32_t hash)
{
    struct continuum *c;

    ASSERT(continuum != NULL);
    ASSERT(ncontinuum != 0);

    c = continuum + hash % ncontinuum;
    ASSERT( c->status > 0  );
    log_debug(LOG_VERB, "NEW choose No. %d continuum,hash:%u ,ncontinuum: %u",hash%ncontinuum,hash,ncontinuum);

    return c->newindex;
}

uint32_t
modhash_transfer_status (struct continuum *continuum, uint32_t ncontinuum, uint32_t hash)
{
    struct continuum *c;

    ASSERT(continuum != NULL);
    ASSERT(ncontinuum != 0);

    c = continuum + hash % ncontinuum;
    ASSERT(c->status > 0);
    log_debug(LOG_VERB, "modhash_transfer_status No. %d continuum,hash:%u ,ncontinuum: %u status:%d",hash%ncontinuum,hash,ncontinuum,c->status);
    return (c->status );
}

/* update continuum, please add a pool->mutex before call me
*/
rstatus_t
modhash_bucket_set_status (struct continuum *continuum, uint32_t ncontinuum, uint32_t hash, int new_status, int require_status)
{
    struct continuum *c;
    int old_status;

    ASSERT(continuum != NULL);
    ASSERT(ncontinuum != 0);

    c = continuum + hash % ncontinuum;
    ASSERT(c->status > 0);
    ASSERT(new_status > 0);
    old_status = c->status;
    if (require_status > -1 && old_status != require_status) {
    	log_error ( "warn: modhash_bucket_set_status set slot %d status from %d (now:%d) to %d failed, may be a adddone is executed",
    			hash % ncontinuum, require_status, c->status, new_status);
    	return NC_ERROR;
    }

    c->status = new_status;
    return (NC_OK);
}
