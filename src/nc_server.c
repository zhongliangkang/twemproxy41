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

#include <stdlib.h>
#include <unistd.h>

#include <nc_core.h>
#include <nc_server.h>
#include <nc_conf.h>

#include <hashkit/nc_hashkit.h>

//static rstatus_t server_set_new_owner(void * elem, void *data);

static struct sp_config  sp_config_arr[]={
    /*
    { string("addrstr"),
        sp_get_string,
        offsetof(struct server_pool, addrstr) },
    { string("name"),
        sp_get_string,
        offsetof(struct server_pool, name ) },
    { string("hash_tag"),
        sp_get_string,
        offsetof(struct server_pool, hash_tag) },

    { string("port"),
        sp_get_num_u16,
        offsetof(struct server_pool, port ) },
    { string("server_retry_timeout"),
        sp_get_num_i64,
        offsetof(struct server_pool, server_retry_timeout) },
    { string("server_failure_limit"),
        sp_get_num_u32,
        offsetof(struct server_pool, server_failure_limit) },
    { string("backlog"),
        sp_get_num_i32,
        offsetof(struct server_pool, backlog) },
    { string("server_connections"),
        sp_get_num_u32,
        offsetof(struct server_pool, server_connections ) },

    { string("key_hash_type"),
        sp_get_hash,
        offsetof(struct server_pool, key_hash_type) },

    { string("dist_type"),
        sp_get_distribution,
        offsetof(struct server_pool, dist_type) },
        */
    { string("server"),
        sp_get_server,
        offsetof(struct server_pool, server) },
    { string("transinfo"),
               sp_get_transinfo,
               offsetof(struct server_pool, server) },

    null_config
};


/* copy server to another
static rstatus_t
nc_server_copy(struct server *old, struct server *new){
    struct server *p,*q;
    p = old;
    q = new;

    q->idx  = p->idx;
    q->owner= p->owner;

    q->pname= p->pname;
    q->name = p->name;
    q->port = p->port;
    q->weight   = p->weight;

    q->family   = p->family;
    q->addrlen  = p->addrlen;
    q->addr     = p->addr;

    q->app      = p->app;
    q->status   = p->status;
    q->seg_start= p->seg_start;
    q->seg_end  = p->seg_end;

    q->ns_conn_q= p->ns_conn_q;
    q->s_conn_q = p->s_conn_q;

    q->next_retry   = p->next_retry;
    q->failure_count= p->failure_count;

    return NC_OK;
}
*/


void
server_ref(struct conn *conn, void *owner)
{
    struct server *server = owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner == NULL);

    conn->family = server->family;
    conn->addrlen = server->addrlen;
    conn->addr = server->addr;

    server->ns_conn_q++;
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    conn->owner = owner;

    log_debug(LOG_VVERB, "ref conn %p owner %p into '%.*s", conn, server,
              server->pname.len, server->pname.data);
}

void
server_unref(struct conn *conn)
{
    struct server *server;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner != NULL);

    server = conn->owner;
    conn->owner = NULL;

    ASSERT(server->ns_conn_q != 0);
    server->ns_conn_q--;
    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);

    log_debug(LOG_VVERB, "unref conn %p owner %p from '%.*s'", conn, server,
              server->pname.len, server->pname.data);
}

int
server_timeout(struct conn *conn)
{
    struct server *server;
    struct server_pool *pool;

    ASSERT(!conn->client && !conn->proxy);

    server = conn->owner;
    pool = server->owner;

    return pool->timeout;
}

bool
server_active(struct conn *conn)
{
    ASSERT(!conn->client && !conn->proxy);

    if (!TAILQ_EMPTY(&conn->imsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (!TAILQ_EMPTY(&conn->omsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->rmsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->smsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    log_debug(LOG_VVERB, "s %d is inactive", conn->sd);

    return false;
}

static rstatus_t
server_each_set_owner(void *elem, void *data)
{
    struct server *s = elem;
    struct server_pool *sp = data;

    s->owner = sp;

    return NC_OK;
}

rstatus_t
server_init(struct array *server, struct array *conf_server,
            struct server_pool *sp)
{
    rstatus_t status;
    uint32_t nserver;

    nserver = array_n(conf_server);
    ASSERT(nserver != 0 && nserver < NC_MAX_NSERVER);
    ASSERT(array_n(server) == 0);


    status = array_init(server, NC_MAX_NSERVER, sizeof(struct server));
    if (status != NC_OK) {
        return status;
    }

    log_debug(LOG_VVVERB, "pre alloc %d server, size:%d bytes", NC_MAX_NSERVER, NC_MAX_NSERVER * sizeof(struct server));

    /* transform conf server to server */
    status = array_each(conf_server, conf_server_each_transform, server);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }
    ASSERT(array_n(server) == nserver);

    /* set server owner */
    status = array_each(server, server_each_set_owner, sp);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" servers in pool %"PRIu32" '%.*s'",
              nserver, sp->idx, sp->name.len, sp->name.data);

    return NC_OK;
}

void
server_deinit(struct array *server)
{
    uint32_t i, nserver;

    for (i = 0, nserver = array_n(server); i < nserver; i++) {
        struct server *s;

        s = array_pop(server);
        ASSERT(TAILQ_EMPTY(&s->s_conn_q) && s->ns_conn_q == 0);
    }
    array_deinit(server);
}

struct conn *
server_conn(struct server *server)
{
    struct server_pool *pool;
    struct conn *conn;

    pool = server->owner;

    /*
     * FIXME: handle multiple server connections per server and do load
     * balancing on it. Support multiple algorithms for
     * 'server_connections:' > 0 key
     */

    if (server->ns_conn_q < pool->server_connections) {
        return conn_get(server, false, pool->redis);
    }
    ASSERT(server->ns_conn_q == pool->server_connections);

    /*
     * Pick a server connection from the head of the queue and insert
     * it back into the tail of queue to maintain the lru order
     */
    conn = TAILQ_FIRST(&server->s_conn_q);
    ASSERT(!conn->client && !conn->proxy);

    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    return conn;
}

static rstatus_t
server_each_preconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server *server;
    struct server_pool *pool;
    struct conn *conn;

    server = elem;
    pool = server->owner;

    conn = server_conn(server);
    if (conn == NULL) {
        return NC_ENOMEM;
    }

    status = server_connect(pool->ctx, server, conn);
    if (status != NC_OK) {
        log_error("connect to server '%.*s' failed, ignored: %s",
                 server->pname.len, server->pname.data, strerror(errno));
        server_close(pool->ctx, conn);
    }

    return NC_OK;
}

static rstatus_t
server_each_disconnect(void *elem, void *data)
{
    struct server *server;
    struct server_pool *pool;

    server = elem;
    pool = server->owner;

    while (!TAILQ_EMPTY(&server->s_conn_q)) {
        struct conn *conn;

        ASSERT(server->ns_conn_q > 0);

        conn = TAILQ_FIRST(&server->s_conn_q);
        conn->close(pool->ctx, conn);
    }

    return NC_OK;
}

static void
server_failure(struct context *ctx, struct server *server)
{
    struct server_pool *pool = server->owner;
    int64_t now, next;
    rstatus_t status;

    if (!pool->auto_eject_hosts) {
        return;
    }

    server->failure_count++;

    log_debug(LOG_VERB, "server '%.*s' failure count %"PRIu32" limit %"PRIu32,
              server->pname.len, server->pname.data, server->failure_count,
              pool->server_failure_limit);

    if (server->failure_count < pool->server_failure_limit) {
        return;
    }

    now = nc_usec_now();
    if (now < 0) {
        return;
    }

    stats_server_set_ts(ctx, server, server_ejected_at, now);

    next = now + pool->server_retry_timeout;

    log_debug(LOG_INFO, "update pool %"PRIu32" '%.*s' to delete server '%.*s' "
              "for next %"PRIu32" secs", pool->idx, pool->name.len,
              pool->name.data, server->pname.len, server->pname.data,
              pool->server_retry_timeout / 1000 / 1000);

    stats_pool_incr(ctx, pool, server_ejects);

    server->failure_count = 0;
    server->next_retry = next;

    status = server_pool_run(pool);
    if (status != NC_OK) {
        log_error("updating pool %"PRIu32" '%.*s' failed: %s", pool->idx,
                  pool->name.len, pool->name.data, strerror(errno));
    }
}

static void
server_close_stats(struct context *ctx, struct server *server, err_t err,
                   unsigned eof, unsigned connected)
{
    if (connected) {
        stats_server_decr(ctx, server, server_connections);
    }

    if (eof) {
        stats_server_incr(ctx, server, server_eof);
        return;
    }

    switch (err) {
    case ETIMEDOUT:
        stats_server_incr(ctx, server, server_timedout);
        break;
    case EPIPE:
    case ECONNRESET:
    case ECONNABORTED:
    case ECONNREFUSED:
    case ENOTCONN:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    default:
        stats_server_incr(ctx, server, server_err);
        break;
    }
}

void
server_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg, *nmsg; /* current and next message */
    struct conn *c_conn;    /* peer client connection */

    ASSERT(!conn->client && !conn->proxy);

    server_close_stats(ctx, conn->owner, conn->err, conn->eof,
                       conn->connected);

    if (conn->sd < 0) {
        server_failure(ctx, conn->owner);
        conn->unref(conn);
        conn_put(conn);
        return;
    }

    for (msg = TAILQ_FIRST(&conn->imsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server inq */
        conn->dequeue_inq(ctx, conn, msg);

        /*
         * Don't send any error response, if
         * 1. request is tagged as noreply or,
         * 2. client has already closed its connection
         */
        if (msg->swallow || msg->noreply) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;

            if (msg->frag_owner != NULL) {
                msg->frag_owner->nfrag_done++;
            }

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->evb, msg->owner);
            }

            log_debug(LOG_INFO, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->imsg_q));

    for (msg = TAILQ_FIRST(&conn->omsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server outq */
        conn->dequeue_outq(ctx, conn, msg);

        if (msg->swallow) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;
            if (msg->frag_owner != NULL) {
                msg->frag_owner->nfrag_done++;
            }

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->evb, msg->owner);
            }

            log_debug(LOG_INFO, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->omsg_q));

    msg = conn->rmsg;
    if (msg != NULL) {
        conn->rmsg = NULL;

        ASSERT(!msg->request);
        ASSERT(msg->peer == NULL);

        rsp_put(msg);

        log_debug(LOG_INFO, "close s %d discarding rsp %"PRIu64" len %"PRIu32" "
                  "in error", conn->sd, msg->id, msg->mlen);
    }

    ASSERT(conn->smsg == NULL);

    server_failure(ctx, conn->owner);

    conn->unref(conn);

    status = close(conn->sd);
    if (status < 0) {
        log_error("close s %d failed, ignored: %s", conn->sd, strerror(errno));
    }
    conn->sd = -1;

    conn_put(conn);
}

rstatus_t
server_connect(struct context *ctx, struct server *server, struct conn *conn)
{
    rstatus_t status;
    rstatus_t con_ret;

    ASSERT(!conn->client && !conn->proxy);

    if (conn->sd > 0) {
        /* already connected on server connection */
        return NC_OK;
    }

    log_debug(LOG_VVERB, "connect to server '%.*s'", server->pname.len,
              server->pname.data);

    conn->sd = socket(conn->family, SOCK_STREAM, 0);
    if (conn->sd < 0) {
        log_error("socket for server '%.*s' failed: %s", server->pname.len,
                  server->pname.data, strerror(errno));
        status = NC_ERROR;
        goto error;
    }

    status = nc_set_nonblocking(conn->sd);
    if (status != NC_OK) {
        log_error("set nonblock on s %d for server '%.*s' failed: %s",
                  conn->sd, server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    if (server->pname.data[0] != '/') {
        status = nc_set_tcpnodelay(conn->sd);
        if (status != NC_OK) {
            log_warn("set tcpnodelay on s %d for server '%.*s' failed, ignored: %s",
                     conn->sd, server->pname.len, server->pname.data,
                     strerror(errno));
        }
    }

    status = event_add_conn(ctx->evb, conn);
    if (status != NC_OK) {
        log_error("event add conn s %d for server '%.*s' failed: %s",
                  conn->sd, server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    ASSERT(!conn->connecting && !conn->connected);

    status = connect(conn->sd, conn->addr, conn->addrlen);
    if (status != NC_OK) {
        if (errno == EINPROGRESS) {
            conn->connecting = 1;
            log_debug(LOG_DEBUG, "connecting on s %d to server '%.*s'",
                      conn->sd, server->pname.len, server->pname.data);
            if (server->owner->b_redis_pass) {
            	goto con_ok;
            } else {
            	return NC_OK;
            }
        }

        log_error("connect on s %d to server '%.*s' failed: %s", conn->sd,
                  server->pname.len, server->pname.data, strerror(errno));

        goto error;
    }

    ASSERT(!conn->connecting);
    conn->connected = 1;
    log_debug(LOG_INFO, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);


con_ok:
    log_error( "auth to server %s sd:%d",server->pname.data, conn->sd);

    con_ret = server_send_redis_auth(ctx, conn);

    if(con_ret != NC_OK ){
        log_error("authentication failed when connect to redis.");
        conn->err = errno;
        return NC_ERROR;
    }


    return NC_OK;

error:
    conn->err = errno;
    return status;
}

void
server_connected(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connecting && !conn->connected);

    stats_server_incr(ctx, server, server_connections);

    conn->connecting = 0;
    conn->connected = 1;

    log_debug(LOG_INFO, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);
}

void
server_ok(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connected);

    if (server->failure_count != 0) {
        log_debug(LOG_VERB, "reset server '%.*s' failure count from %"PRIu32
                  " to 0", server->pname.len, server->pname.data,
                  server->failure_count);
        server->failure_count = 0;
        server->next_retry = 0LL;
    }
}

static rstatus_t
server_pool_update(struct server_pool *pool)
{
    rstatus_t status;
    int64_t now;
    uint32_t pnlive_server; /* prev # live server */

    if (!pool->auto_eject_hosts) {
        return NC_OK;
    }

    if (pool->next_rebuild == 0LL) {
        return NC_OK;
    }

    now = nc_usec_now();
    if (now < 0) {
        return NC_ERROR;
    }

    if (now <= pool->next_rebuild) {
        if (pool->nlive_server == 0) {
            errno = ECONNREFUSED;
            return NC_ERROR;
        }
        return NC_OK;
    }

    pnlive_server = pool->nlive_server;

    status = server_pool_run(pool);
    if (status != NC_OK) {
        log_error("updating pool %"PRIu32" with dist %d failed: %s", pool->idx,
                  pool->dist_type, strerror(errno));
        return status;
    }

    log_debug(LOG_INFO, "update pool %"PRIu32" '%.*s' to add %"PRIu32" servers",
              pool->idx, pool->name.len, pool->name.data,
              pool->nlive_server - pnlive_server);


    return NC_OK;
}

uint32_t
server_pool_hash(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    ASSERT(array_n(&pool->server) != 0);

    if (array_n(&pool->server) == 1) {
        return 0;
    }

    ASSERT(key != NULL && keylen != 0);

    return pool->key_hash((char *)key, keylen);
}


uint32_t
server_pool_idx(struct server_pool *pool, uint8_t *key, uint32_t keylen, int redirect)
{
    uint32_t hash, idx;

    ASSERT(array_n(&pool->server) != 0);
    ASSERT(key != NULL && keylen != 0);

    /*
     * If hash_tag: is configured for this server pool, we use the part of
     * the key within the hash tag as an input to the distributor. Otherwise
     * we use the full key
     */
    if (!string_empty(&pool->hash_tag)) {
        struct string *tag = &pool->hash_tag;
        uint8_t *tag_start, *tag_end;

        tag_start = nc_strchr(key, key + keylen, tag->data[0]);
        if (tag_start != NULL) {
            tag_end = nc_strchr(tag_start + 1, key + keylen, tag->data[1]);
            if ((tag_end != NULL) && (tag_end - tag_start > 1)) {
                key = tag_start + 1;
                keylen = (uint32_t)(tag_end - key);
            }
        }
    }

    switch (pool->dist_type) {
    case DIST_KETAMA:
        hash = server_pool_hash(pool, key, keylen);
        idx = ketama_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_MODULA:
        hash = server_pool_hash(pool, key, keylen);
        idx = modula_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_RANDOM:
        idx = random_dispatch(pool->continuum, pool->ncontinuum, 0);
        break;

    case DIST_MODHASH:
        hash = server_pool_hash(pool, key, keylen);

        if (redirect > 0) {
        	idx = modhash_dispatch_newserver(pool->continuum, pool->ncontinuum, hash);
        } else {
        	idx = modhash_dispatch(pool->continuum, pool->ncontinuum, hash);
        }
        break;


    default:
        NOT_REACHED();
        return 0;
    }
    ASSERT(idx < array_n(&pool->server));
    return idx;
}

struct server *
server_pool_server(struct server_pool *pool, uint8_t *key, uint32_t keylen, int redirect)
{
    struct server *server;
    uint32_t idx;

    idx = server_pool_idx(pool, key, keylen, redirect);
    server = array_get(&pool->server, idx);

    log_debug(LOG_VERB, "key '%.*s' on dist %d maps to server '%.*s'", keylen,
              key, pool->dist_type, server->pname.len, server->pname.data);

    return server;
}

struct conn *
server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key,
                 uint32_t keylen, struct msg* msg)
{
    rstatus_t status;
    struct server *server;
    struct conn *conn;

    status = server_pool_update(pool);
    if (status != NC_OK) {
        return NULL;
    }

    /* from a given {key, keylen} pick a server from pool */
    server = server_pool_server(pool, key, keylen, msg->redirect);
    if (server == NULL) {
        return NULL;
    }


    /* REDIRECT: CLIENT->PROXY-(*)->OLDSERERR->PROXY->NEWSERVER->PROXY */
    if (server->owner->status == SERVER_STATUS_TRANSING &&
    	  server->owner->dist_type == DIST_MODHASH &&
    	   msg->redirect < MAX_REDIRECT_TIMES
    	  ) {
    	uint32_t hash = server_pool_hash(pool, key, keylen);
    	msg->transfer_status = modhash_transfer_status(pool->continuum, pool->ncontinuum, hash);


    	log_debug(LOG_VERB, "modhash_transfer_status:key '%.*s' on dist %d transfer_status is %d", keylen,
    	              key, pool->dist_type, msg->transfer_status);
    }

	/*REDIRECT: CLIENT->PROXY->OLDSERERR->PROXY-(4)->NEWSERVER->PROXY
	 * try to update continuum's status
	 * */

	if (1 == msg->redirect && msg->redirect_type == REDIRECT_TYPE_BUCKET_TRANS_DONE) {
		pthread_mutex_lock(&pool->mutex);
		//log_error("pthread_mutex_lock for modhash_bucket_set_status");
		uint32_t hash = server_pool_hash(pool, key, keylen);
		status = modhash_bucket_set_status(pool->continuum, pool->ncontinuum, hash, CONTINUUM_STATUS_TRANSED, CONTINUUM_STATUS_TRANSING);
		pthread_mutex_unlock(&pool->mutex);
		//log_error("pthread_mutex_unlock for modhash_bucket_set_status");
		if (status == NC_OK) {
			log_debug(LOG_VERB, "modhash_transfer_status:key '%.*s' on dist %d transfer_status UPDATE TO %d succ", keylen,
					key, pool->dist_type, CONTINUUM_STATUS_TRANSED);
		} else {
			log_error("modhash_transfer_status:key '%.*s' on dist %d transfer_status UPDATE TO %d failed", keylen, key, pool->dist_type,
					CONTINUUM_STATUS_TRANSED);
		}
	}


    /* reload server config here */
    if (server->reload_svr){
        /* make sure the mif is OK */
        ASSERT(server->mif.ski && server->mif.new_name && server->mif.new_pname);

        /* lock for safe */
        pthread_mutex_lock(&server->mutex);

        if(server->reload_svr){   /* for safe */
            if(server->sock_need_free){
                nc_free(server->sock_info);
            }else{
                server->sock_need_free = true;  /* first modified */
            }

            server->family = server->mif.ski->family;
            server->addrlen= server->mif.ski->addrlen;
            server->addr   = (struct sockaddr*)&server->mif.ski->addr;
            server->sock_info = server->mif.ski;

            nc_free(server->pname.data);
            nc_free(server->name.data);
            server->pname.data = (uint8_t*)server->mif.new_pname;
            server->pname.len  = (uint32_t)nc_strlen(server->mif.new_pname);
            server->name.data = (uint8_t*)server->mif.new_name;
            server->name.len  = (uint32_t)nc_strlen(server->mif.new_name);
            log_error ("do reload %.*s", server->name.len, server->name.data);

            struct server_pool *tpool= server->owner;
            while(!TAILQ_EMPTY(&server->s_conn_q)){
                ASSERT(server->ns_conn_q > 0 );
                conn = TAILQ_FIRST(&server->s_conn_q);
				core_close(tpool->ctx, conn);
				/* core_close is equal conn->colse + event_del_conn */
                //conn->close(tpool->ctx, conn);
            }

            /* reload OK */
            server->reload_svr = false;
        }
        
        pthread_mutex_unlock(&server->mutex);
    }


    /* pick a connection to a given server from  */

    conn = server_conn(server);
    if (conn == NULL) {
        return NULL;
    }

    /* try to connect if not*/
    status = server_connect(ctx, server, conn);
    if (status != NC_OK) {
        server_close(ctx, conn);
        return NULL;
    }


    return conn;
}

static rstatus_t
server_pool_each_preconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    if (!sp->preconnect) {
        return NC_OK;
    }

    status = array_each(&sp->server, server_each_preconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

rstatus_t
server_pool_preconnect(struct context *ctx)
{
    rstatus_t status;

    status = array_each(&ctx->pool, server_pool_each_preconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_disconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    status = array_each(&sp->server, server_each_disconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

void
server_pool_disconnect(struct context *ctx)
{
    array_each(&ctx->pool, server_pool_each_disconnect, NULL);
}

static rstatus_t
server_pool_each_set_owner(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    sp->ctx = ctx;

    return NC_OK;
}

static rstatus_t
server_pool_each_calc_connections(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    ctx->max_nsconn += sp->server_connections * array_n(&sp->server);
    ctx->max_nsconn += 1; /* pool listening socket */

    return NC_OK;
}

rstatus_t
server_pool_run(struct server_pool *pool)
{
	rstatus_t rt;
    ASSERT(array_n(&pool->server) != 0);

    switch (pool->dist_type) {
    case DIST_KETAMA:
        return ketama_update(pool);

    case DIST_MODULA:
        return modula_update(pool);

    case DIST_RANDOM:
        return random_update(pool);


    case DIST_MODHASH:
	    pthread_mutex_lock(&pool->mutex);
		//log_error("pthread_mutex_lock for modhash_update");
		rt = modhash_update(pool);
		pthread_mutex_unlock(&pool->mutex);
		//log_error("pthread_mutex_unlock for modhash_update");
        return  rt;

    default:
        NOT_REACHED();
        return NC_ERROR;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_run(void *elem, void *data)
{
    return server_pool_run(elem);
}

rstatus_t
server_pool_init(struct array *server_pool, struct array *conf_pool,
                 struct context *ctx)
{
    rstatus_t status;
    uint32_t npool;

    npool = array_n(conf_pool);
    ASSERT(npool != 0);
    ASSERT(array_n(server_pool) == 0);


    status = array_init(server_pool, npool, sizeof(struct server_pool));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf pool to server pool */
    status = array_each(conf_pool, conf_pool_each_transform, server_pool);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }
    ASSERT(array_n(server_pool) == npool);

    /* set ctx as the server pool owner */
    status = array_each(server_pool, server_pool_each_set_owner, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* compute max server connections */
    ctx->max_nsconn = 0;
    status = array_each(server_pool, server_pool_each_calc_connections, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* update server pool continuum */
    status = array_each(server_pool, server_pool_each_run, NULL);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" pools", npool);

    return NC_OK;
}

void
server_pool_deinit(struct array *server_pool)
{
    uint32_t i, npool;

    for (i = 0, npool = array_n(server_pool); i < npool; i++) {
        struct server_pool *sp;

        sp = array_pop(server_pool);
        ASSERT(sp->p_conn == NULL);
        ASSERT(TAILQ_EMPTY(&sp->c_conn_q) && sp->nc_conn_q == 0);

        if (sp->continuum != NULL) {
            nc_free(sp->continuum);
            sp->ncontinuum = 0;
            sp->nserver_continuum = 0;
            sp->nlive_server = 0;
        }

        server_deinit(&sp->server);

        log_debug(LOG_DEBUG, "deinit pool %"PRIu32" '%.*s'", sp->idx,
                  sp->name.len, sp->name.data);
    }

    array_deinit(server_pool);

    log_debug(LOG_DEBUG, "deinit %"PRIu32" pools", npool);
}



int sp_get_server(struct server_pool *sp, struct sp_config *spc, char * result) {
	uint32_t i;
	char *server_buf;
	int n = 0;
	int result_len = 0;

	server_buf = nc_alloc(STATS_RESULT_BUFLEN);
	if (!server_buf) {
		snprintf(result, STATS_RESULT_BUFLEN, "no memory");
		return NC_ERROR;
	}

	for (i = 0; i < array_n(&sp->server); i++) {
		struct server *server = array_get(&sp->server, i);
		n = 0;
		if (server->status == 0)
			continue;

		pthread_mutex_lock(&server->mutex);

		if (server->reload_svr) {
			n = snprintf(server_buf, STATS_RESULT_BUFLEN, "%s %s %d-%d %d\n", server->mif.new_name, server->app.data, server->seg_start, server->seg_end,
					server->status);
		} else {
			n = snprintf(server_buf, STATS_RESULT_BUFLEN, "%s %s %d-%d %d\n", server->name.data, server->app.data, server->seg_start, server->seg_end,
					server->status);
		}

		pthread_mutex_unlock(&server->mutex);

		if (result_len + n > STATS_RESULT_BUFLEN - 1) {
			n = snprintf(result, STATS_RESULT_BUFLEN, "too many servers in pool %s\n", sp->name.data);
			result_len =n;
			break;
		}

		strncpy(result + result_len, server_buf, n);
		result_len += n;

	}
	result[result_len] = '\0';
	nc_free(server_buf);
	return NC_OK;
}

int sp_get_transinfo( struct server_pool *sp, struct sp_config *spc, char * result){
    int n;
	n = snprintf(result, 1024,"add_avial:%d\nadd_run:%d\n", sp->server.nalloc -sp->server.nelem, sp->add_cmd_count);
    if (n<=0) {
    	snprintf(result, 1024,"unknow error");
    	return NC_ERROR;
    }
    return NC_OK;

}

int sp_get_by_item(char *sp_name, char *sp_item ,char *result, void *sp){
        uint32_t n,m,i;
        struct array *arr = sp;
        int rt;

        struct string item;
        item.data = (void *)sp_item;
        item.len = (uint32_t)nc_strlen(sp_item);

        n = array_n(arr);

        //printf("ctx->stats->p_cf element num: %d\n",n);
        for(i=0;i<n;i++){
                struct server_pool *tcf = array_get(arr,i);
                //printf("sname: %s\n",tcf->name.data);
                //in this server pool
                if(!strcmp(sp_name, (char *)tcf->name.data)){
                         m = array_n(&tcf->server);

                        rt = server_pool_get_config_by_string(tcf, &item, result);
                        if( rt != NC_OK){
                            log_error("get config by string fail: %s",sp_item );
                            snprintf(result,80,"get config by string fail: %s",sp_item );
                            return NC_ERROR;
                        }else{
                            return NC_OK;
                        }

                }
        }

        // not found the config
        snprintf(result,80,"cannot find redis pool %s\n",sp_name );
        return NC_ERROR;

}




int server_pool_get_config_by_string(struct server_pool *sp, struct string *item, char * result){
    struct  sp_config * spp;

    log_debug(LOG_VERB, " in server_pool_get_config_by_string");
    for(spp = sp_config_arr ; spp->name.len != 0; spp++){
        int rv ;

        if(string_compare( item, &spp->name) !=0){
            continue;
        }

        rv = spp->get(sp, spp, result);

        if(rv != NC_OK){
            log_error("server_pool_get_config_by_string error: \"%.*s\" %d", item->len, item->data, rv);
            return NC_ERROR;
        }

        return NC_OK;
    }

    log_error("server_pool_get_config_by_string error: \"%.*s\" is unkown",item->len, item->data);

    return NC_ERROR;

}


rstatus_t nc_stats_addDoneCommand (void *sp, char *sp_name, char *inst, char* app, char *segs, char *status, char *result) {
	uint32_t npool, nserver, i;
	struct array *splist = sp;
	int rt, n;
	struct string item;
	struct server tmpsvr;
	struct server_pool *tcf, *pool;
	uint32_t server_index ;
	char buf[128]; //pname buf


	log_debug(LOG_VERB, "addDoneCommand: %s %s %s %s %s", sp_name, inst, app, segs, status);

	item.data = (uint8_t *) inst;
	item.len = (uint32_t) nc_strlen(inst);

	npool = array_n(splist);
	pool = NULL;
	for (i = 0; i < npool; i++) {
		 tcf = array_get(splist, i);
		//in this server pool
		if (!strcmp(sp_name, (const char*) tcf->name.data)) {
			pool = tcf;
			break;
		}
	}

	if (pool == NULL) {
		snprintf(result, STATS_RESULT_BUFLEN, "pool %s not found", sp_name);
		return NC_ERROR;
	}
	log_debug(LOG_VERB,"match sp name: %s, inst: %s, app:%s, segs: %s, status: %s", pool->name.data, inst,app,segs,status);


	/* step1: precheck  */


	rt = nc_stats_addCommand_parse (pool, inst, app, segs, status, &tmpsvr, result);

	if (rt != NC_OK) {
		return rt;
	}



	/* find status = 2 line*/
	int dstsvr_idx = - 1;
	int dstsvr_num = 0;
	int dstsvr_num_badstatus = 0;
	int srcsvr_idx = - 1;
	int srcsvr_num = 0;

	rt = NC_OK;
	nserver = array_n(&pool->server);
	for (server_index = 0; server_index < nserver; server_index++) {
		struct server *s = array_get(&pool->server, server_index);
		if (s->status == 0) {
			continue;
		}

		if (tmpsvr.seg_start == s->seg_start && tmpsvr.seg_end == s->seg_end
			 && (0 == strncmp((char *) tmpsvr.name.data, (char *) s->name.data,tmpsvr.name.len))) {
			dstsvr_idx = (int ) server_index;
			dstsvr_num ++;
			if (s->status == 1) {
				dstsvr_num_badstatus ++;
				snprintf(result, STATS_RESULT_BUFLEN,"a same name server with status %d exists %s ", s->status, s->name.data);
				log_error(result);
				return NC_ERROR;
			}
		}

		if (s->status == 1 && (			tmpsvr.seg_start == s->seg_start || tmpsvr.seg_end == s->seg_end)) {

			srcsvr_idx = (int ) server_index;
			srcsvr_num  ++;;

		}


	}

	if (dstsvr_num == 0) {
		snprintf(result, STATS_RESULT_BUFLEN,"server '%s %d-%d %d' not found, please add first",tmpsvr.name.data, tmpsvr.seg_start, tmpsvr.seg_end, tmpsvr.status);
		log_error(result);
		return NC_ERROR;
	} else 	if (dstsvr_num > 1) {
		snprintf(result, STATS_RESULT_BUFLEN,"server '%s %d-%d %d' define too many times: %d",tmpsvr.name.data, tmpsvr.seg_start, tmpsvr.seg_end, tmpsvr.status,dstsvr_num);
		log_error(result);
		return NC_ERROR;
	} else 	if (srcsvr_num <= 0) {
		snprintf(result, STATS_RESULT_BUFLEN,"server '%s %d-%d %d' do not have a src svr",tmpsvr.name.data, tmpsvr.seg_start, tmpsvr.seg_end, tmpsvr.status);
		log_error(result);
		return NC_ERROR;
	}


    if(NC_OK != server_check_hash_keys(pool, NULL) ){
    	snprintf(result, STATS_RESULT_BUFLEN,"server_check_hash_keys check failed");
    	log_error(result);
    	return NC_ERROR;
    }


	pthread_mutex_lock(&pool->mutex);
	//log_error("pthread_mutex_lock for migrate segment");

	//int idx  = -1;
	nserver = array_n(&pool->server);
	for (server_index = 0; server_index < nserver; server_index++) {
		struct server *s = array_get(&pool->server, server_index);
		bool update = false;
		if (s->status == 0) {
			continue;
		}

		log_debug(LOG_VERB, "%s %d %d %d", s->name.data, s->status, s->seg_start, s->seg_end);

		if (server_index == (uint32_t) dstsvr_idx) {
			if (tmpsvr.seg_start == s->seg_start && tmpsvr.seg_end == s->seg_end && s->status == 2) {
				if (0 == strncmp((char *) tmpsvr.name.data, (char *) s->name.data, tmpsvr.name.len)) {
					s->status = 1;
					update = true;
				} else {
					log_debug(LOG_VERB, "error %s %d ne %s %d ", s->name.data, s->name.len, tmpsvr.name.data, tmpsvr.name.len);
				}
			}

		} else {
			/*
			 *  old  0-419999 1   ==> a+1 - 419999 1
			 *  new  0-a      2   ==> 0   - a      1
			 */
			if (s->seg_start == tmpsvr.seg_start && tmpsvr.seg_end <= s->seg_end) {
				s->seg_start = tmpsvr.seg_end + 1;
				s->status = 1;
				if (s->seg_start > s->seg_end) {
					s->status = 0;
				}
				log_error("s->seg_start <= tmpsvr.seg_start && s->seg_end > tmpsvr.seg_start && s->seg_end < tmpsvr.seg_end");
				update = true;

			}
			/*
			 * old 0-219999 1 ==> 0-0      0
			 * new 0-419999 2 ==> 0-419999 1
			 */
			else if (s->seg_start == tmpsvr.seg_start && tmpsvr.seg_end > s->seg_end) {
				s->status = 0;
				log_error("s->seg_start == tmpsvr.seg_start && tmpsvr.seg_end  >  s->seg_end");
				update = true;
			}
			/*
			 *  old  0-419999 1   ==> 0 - a+1     1
			 *  new  a-419999 2   ==> a - 419999   1
			 */
			else if (s->seg_end == tmpsvr.seg_end && s->seg_start <= tmpsvr.seg_start) {
				s->seg_end = tmpsvr.seg_start - 1;
				s->status = 1;
				if (s->seg_start > s->seg_end) {
					s->status = 0;
				}
				log_error("s->seg_end == tmpsvr.seg_end && s->seg_start <= tmpsvr.seg_start");
				update = true;
			}
			/*
			 * old 220000-419999 1 ==> 0-0      0
			 * new 0-419999 2 ==> 0-419999 1
			 */
			else if (s->seg_end == tmpsvr.seg_end && s->seg_start > tmpsvr.seg_start) {
				s->status = 0;
				log_error("s->seg_end == tmpsvr.seg_end && s->seg_start > tmpsvr.seg_start");
				update = true;
			} else {
				log_error("adddone: %s not match %s", s->pname.data, tmpsvr.pname.data);
			}

		}
		/*
		 *
		 127.0.0.1:30001:1 pvz1 100000-199999 1
		 */
		if (update) {
			n = snprintf(buf, 128, "%s:1 %s %d-%d %d", s->name.data, s->app.data, s->seg_start, s->seg_end, s->status);
			if (n == 1024 || n <= 0) {
				//error
			}

			log_error("add done %s => %s", s->pname.data, buf);

			string_deinit(&s->pname);
			string_copy(&s->pname, (uint8_t *) buf, (uint32_t) strlen(buf));

		}
	}
	pthread_mutex_unlock(&pool->mutex);
	//log_error("pthread_mutex_unlock for migrate segment");

	if (rt != NC_OK) {

		return NC_ERROR;
	} else {

	}


	/* step3: do update modhash */

    pthread_mutex_lock(&pool->mutex);
    //log_error("pthread_mutex_lock for modhash_update");
	rt = modhash_update(pool);
    pthread_mutex_unlock(&pool->mutex);
    //log_error("pthread_mutex_unlock for modhash_update");

	if (rt != NC_OK) {
		log_error("fetal error:modhash_update failed");
		return NC_ERROR;
	}

	rt = sp_write_conf_file(pool, 0, -1, 0);
	if (rt != NC_OK) {
		log_error("error: sp_write_conf_file failed");
	}

	return NC_OK;
}



rstatus_t nc_stats_addCommand (void *sp, char *sp_name, char *inst, char* app, char *segs, char *status, char *result) {
	uint32_t n, i;
	struct array *arr = sp;
	int rt;
	struct string item;
	struct server tmpsvr;
	struct server_pool *pool;
    int add_again = 0; // if run add command the second time.

	log_debug(LOG_VERB, "nc_add_a_server: add %s %s %s %s %s", sp_name, inst, app, segs, status);

	item.data = (uint8_t *) inst;
	item.len = (uint32_t) nc_strlen(inst);


	pool = NULL;
	n = array_n(arr);
	for (i = 0; i < n; i++) {
		struct server_pool *tcf = array_get(arr, i);
		//in this server pool
		if (!strcmp(sp_name, (const char*) tcf->name.data)) {
//			log_debug(LOG_VERB,"nc_add_a_server pool: %s, inst: %s, app:%s, segs: %s, status: %s", sp_name,inst,app,segs,status);
			pool = tcf;
			break;
		}
	}

	if (pool == NULL) {
		snprintf(result, STATS_RESULT_BUFLEN, "pool %s not found", sp_name);
		return NC_ERROR;
	}

	/* step1: precheck  */

	rt = nc_stats_addCommand_parse(pool, inst, app, segs, status, &tmpsvr, result);

	if (rt != NC_OK) {
		log_error("new add server to %s precheck failed: reason: %s", sp_name, result);
		return NC_ERROR;
	} else {
		log_debug(LOG_VERB, "nc_add_a_server:%s %s %s %s %s arg check ok", sp_name, inst, app, segs, status);
	}



	//check seg
	uint32_t server_index;
	uint32_t nserver = array_n(&pool->server);
	int seg_ok = 1;
	//int old_server_idx = -1;
	for (server_index = 0; server_index < nserver; server_index++) {
		struct server *s = (struct server *) array_get(&pool->server, server_index);

        // we reset add_again flag to 0 for each server
        add_again = 0;
		if (s->status == 0) {
			continue;
		}

		// tmpsvr in s or tmpsvr union s > 0
		if ((tmpsvr.seg_start >= s->seg_start && tmpsvr.seg_start <= s->seg_end)
				  || (tmpsvr.seg_end >= s->seg_start && tmpsvr.seg_end <= s->seg_end ) ) {

			if (0 == string_compare(&tmpsvr.name, &s->name)) {
                if( tmpsvr.status == 2  && s->status == 2 &&
                        (tmpsvr.seg_start == s->seg_start && tmpsvr.seg_end == s->seg_end) ){
                    add_again = 1;
                    // do nothing.
                    // the same operation. we allowed add command to run twice.
                }else{
                    snprintf(result, STATS_RESULT_BUFLEN, "cannot transfer to same instance %s status:%d -> %s status:%d",
                            s->pname.data, s->status, tmpsvr.pname.data, tmpsvr.status) ;
                    goto err;
                }
			}

			if (tmpsvr.seg_start != s->seg_start && tmpsvr.seg_end != s->seg_end) {
				snprintf(result, STATS_RESULT_BUFLEN, " %s is not contain a valid dst segment", tmpsvr.pname.data);
				goto err;
			}

			if (s->status == 1) {
				seg_ok ++;
			} else if (s->status == 2 || s->status == 3) {
                if(add_again == 0){
                    snprintf(result, STATS_RESULT_BUFLEN, "seg is in transfering %s", s->pname.data);
                    goto err;
                }
			} else {
				//NO REACH
			}
		}

	}

    // run again. we need not to update the pool.
    if(add_again){
        string_deinit ( &tmpsvr.app);
        string_deinit ( &tmpsvr.name);
        string_deinit ( &tmpsvr.pname);
        return NC_OK;
    }


    if(NC_OK != server_check_hash_keys(pool, NULL) ){
     	snprintf(result, STATS_RESULT_BUFLEN,"server_check_hash_keys check failed");
     	log_error(result);
     	return NC_ERROR;
     }


    pthread_mutex_lock(&pool->mutex);
	//log_error("pthread_mutex_lock for nc_add_new_server");
	nc_add_new_server(pool, &tmpsvr, result);
	pthread_mutex_unlock(&pool->mutex);
	//log_error("pthread_mutex_unlock for nc_add_new_server");

	string_deinit ( &tmpsvr.app);
	string_deinit ( &tmpsvr.name);
	string_deinit ( &tmpsvr.pname);

	/* step3: do update modhash */
    pthread_mutex_lock(&pool->mutex);
	//log_error("pthread_mutex_lock for modhash_update");
	rt = modhash_update(pool);
	if (rt == NC_OK) {
		pool->add_cmd_count ++;
	}
	pthread_mutex_unlock(&pool->mutex);
	//log_error("pthread_mutex_unlock for modhash_update");
	if (rt != NC_OK) {
		log_error("fetal error:modhash_update failed");
		return NC_ERROR;
	}


	rt = sp_write_conf_file(pool, i, -1, 0);
	if (rt != NC_OK) {
		log_error("error: sp_write_conf_file failed");
	}

	return NC_OK;


err:
	string_deinit ( &tmpsvr.app); //deinit 2 times
	string_deinit ( &tmpsvr.name);
	string_deinit ( &tmpsvr.pname);
	// not found the config

	return NC_ERROR;

}

/* precheck for adding a server to a server_pool */
rstatus_t nc_stats_addCommand_parse(struct server_pool *sp, char * inst, char * app, char * segs, char* status, struct server* tmpsvr, char* result) {
	struct string sp_app;
	struct array *server;
	struct server *svr;
	uint32_t n_old_svrs;

	int port, seg_start, seg_end, istatus;
	size_t ip_len, port_len, seg_start_len;
	//struct sockinfo *ski;
	rstatus_t ret;
	uint8_t *pc;
	char pname_buf[1024];
	int n;

	//struct string addr;

	server = &sp->server;
	n_old_svrs = array_n(server);

	if (n_old_svrs <= 0) {
		snprintf(result, STATS_RESULT_BUFLEN, "bad server num %d", n_old_svrs);
		return NC_ERROR;
	}

	if (server->nelem == server->nalloc) {
		snprintf(result, STATS_RESULT_BUFLEN, "too many servers, server nelem is up to %d, cannot be alloc new item, please restart process!", server->nelem);
		return NC_ERROR;
	}

	//get the first server info
	svr = array_get(server, 0);
	sp_app = svr->app;

	// app is different
	if (strcmp(app, (const char*) sp_app.data)) {
		snprintf(result, STATS_RESULT_BUFLEN, "bad app, new %s vs old %s", app, svr->app.data);
		return NC_ERROR;
	}

	// MODHASH NEQ modhash
	if ((sp->dist_type != DIST_MODHASH)) {
		snprintf(result, STATS_RESULT_BUFLEN, "bad dist_type, should be modhash");
		return NC_ERROR;
	}

	ip_len = 0;

	pc = nc_strchr(inst, inst + nc_strlen(inst), ':');

	if (pc) {
		ip_len = (size_t) (pc - (uint8_t *) inst);
		port_len = nc_strlen(pc + 1);
	}

	if (ip_len == 0 || port_len == 0) {
		snprintf(result, STATS_RESULT_BUFLEN, "bad name %s", inst);
		return NC_ERROR;
	}

	port = nc_atoi(inst+ip_len+1, port_len);

	seg_start_len = 0;
	pc = nc_strchr(segs, segs + nc_strlen(segs), '-');

	if (!pc) {
		snprintf(result, STATS_RESULT_BUFLEN, "bad segment %s", segs);
		return NC_ERROR;
	}

	seg_start_len = (size_t) (pc - (uint8_t *) segs);
	if (seg_start_len == strlen(segs)) {
		seg_start = seg_end = nc_atoi(segs, seg_start_len);
	} else {
		seg_start = nc_atoi(segs, seg_start_len);
		seg_end = nc_atoi(segs+seg_start_len+1, strlen(segs)-seg_start_len-1);
	}

	istatus = nc_atoi(status, 1);

	if (istatus != 2) {
			snprintf(result, STATS_RESULT_BUFLEN, "bad status %s",status);
			return NC_ERROR;
	}

	if (port  <= 0  || port > 65535 ) {
			snprintf(result, STATS_RESULT_BUFLEN, "bad ip:port %s",inst);
			return NC_ERROR;
	}

	if (seg_start > seg_end || seg_start < 0 || seg_end < 0 || seg_start >= MODHASH_TOTAL_KEY || seg_end >= MODHASH_TOTAL_KEY) {
		snprintf(result, STATS_RESULT_BUFLEN, "bad segment %s", segs);
		return NC_ERROR;
	}

	tmpsvr->port = (uint16_t) port;
	tmpsvr->weight = 1;
		//pname 127.0.0.1:30003:1 pvz1 0-99999 2, use in write conf
	n = snprintf(pname_buf, 1024, "%s:%d %s %s %d", inst, tmpsvr->weight, app, segs, 2);
	if (n>0 && n< 1024) {
		//FIXME add some check
	}

	string_init(&tmpsvr->pname);
	string_init(&tmpsvr->name);
	string_init(&tmpsvr->app);

	ret = string_copy(&tmpsvr->pname, (const uint8_t *)pname_buf, (uint32_t)strlen(pname_buf));
	if (ret != NC_OK) {
		goto err;
	}

	ret = string_copy(&tmpsvr->name, (uint8_t *) inst, (uint32_t) strlen(inst));
	if (ret != NC_OK) {
		goto err;
	}

	ret = string_copy(&tmpsvr->app, (uint8_t *) app, (uint32_t) strlen(app));
	if (ret != NC_OK) {
		goto err;
	}

	/* app */
	tmpsvr->seg_start = seg_start;
	tmpsvr->seg_end = seg_end;
	tmpsvr->status = istatus;

	return NC_OK;

err:
	string_deinit(&tmpsvr->pname);
	string_deinit(&tmpsvr->name);
	string_deinit(&tmpsvr->app);
	return NC_ERROR;
}

/* precheck for adding a server to a server_pool */
rstatus_t nc_add_new_server(struct server_pool *sp, struct server *tmpsvr, char* result) {
	struct string sp_app;
	struct array *server;
	struct server *svr, *new_svr;
	uint32_t n_old_svrs;

	//int port, seg_start, seg_end, istatus;
	//size_t ip_len, port_len, seg_start_len;
	struct sockinfo *ski;
	rstatus_t ret;
	uint8_t *pc;
	//char pname_buf[1024];
	//int n;

	struct string addr;

	server = &sp->server;
	n_old_svrs = array_n(server);

	if (n_old_svrs <= 0) {
		return NC_ERROR;
	}

	if (server->nelem == server->nalloc) {
		snprintf(result, STATS_RESULT_BUFLEN, "server nelem is up to %d, cannot be alloc new item, please restart process", server->nelem);
		return NC_ERROR;
	}


	//get the first server info
	svr = array_get(server, 0);
	sp_app = svr->app;

	// app is different
	if (strcmp((const char*) tmpsvr->app.data, (const char*) sp_app.data)) {
		snprintf(result, STATS_RESULT_BUFLEN, "new add app '%s' is different from app in server pool '%s'", tmpsvr->app.data, sp_app.data);
		return NC_ERROR;
	}

	// MODHASH NEQ modhash
	if ((sp->dist_type != DIST_MODHASH)) {
		snprintf(result, STATS_RESULT_BUFLEN, "server pool:%s dist_type is not modhash", sp->name.data);
		return NC_ERROR;
	}

	/* precheck ok,start to add new server */
	//snprintf(result,1000,"check ok. svrapp:%s, app: %s ,iplen: %.*s port_len: %.*s . segstart:%d ,seqend:%d ,status:%d\n",sp_app.data,app,ip_len,inst,port_len,inst+ip_len+1,seg_start,seg_end,istatus);
	new_svr = array_push(server);

	ASSERT(new_svr);
	//*new_svr = *tmpsvr;
	string_init (&new_svr->app);
	string_init (&new_svr->name);
	string_init (&new_svr->pname);
	string_copy(&new_svr->app, tmpsvr->app.data, tmpsvr->app.len );
	string_copy(&new_svr->name, tmpsvr->name.data, tmpsvr->name.len );
	string_copy(&new_svr->pname, tmpsvr->pname.data, tmpsvr->pname.len );
	new_svr->seg_end = tmpsvr->seg_end;
	new_svr->seg_start = tmpsvr->seg_start;
	new_svr->status = tmpsvr->status;
	new_svr->weight = tmpsvr->weight;
	new_svr->port = tmpsvr->port;

	new_svr->idx = array_idx(server, new_svr);
	new_svr->owner = sp;

	/* sockinfo */
	ski = (void *) nc_alloc(sizeof(struct sockinfo));
	if (!ski) {
		return NC_ERROR;
	}

	string_init(&addr);
	pc = nc_strchr (tmpsvr->name.data, tmpsvr->name.data + tmpsvr->name.len,  ':');

	if (! pc) {
		string_deinit(&addr);
		return NC_ERROR;
	}

	ret = string_copy(&addr, tmpsvr->name.data, (uint32_t) (pc - tmpsvr->name.data));
	if (ret != NC_OK) {
		return ret;
	}

	ret = nc_resolve(&addr, tmpsvr->port, ski);
	if (ret != NC_OK) {
		return ret;
	}

	new_svr->family = ski->family;
	new_svr->addrlen = ski->addrlen;
	new_svr->addr = (struct sockaddr*) &ski->addr;
	new_svr->sock_need_free = false;
	new_svr->ns_conn_q = 0;
	new_svr->next_retry = 0LL;
	new_svr->failure_count = 0;
	new_svr->reload_svr = false;
	pthread_mutex_init(&new_svr->mutex, NULL);
	TAILQ_INIT(&new_svr->s_conn_q);
	/* init metric */
	ret = stats_pool_add_server(sp, new_svr->idx);

	if (NC_OK != ret) {
		snprintf(result, 1000, "stats_pool_add_server error");
		return ret;
	}
	return NC_OK;
}

/*
static rstatus_t 
server_set_new_owner(void * elem, void *data){
    struct server *server;

    log_debug(LOG_VERB,"in server_set_new_owner\n");

    server = elem;

    struct conn *conn;

    TAILQ_FOREACH(conn, &server->s_conn_q,conn_tqe){
        //printf(" conn address:%d %d\n",&conn->owner, &server);
    }

    return NC_OK;
}
*/

rstatus_t server_check_hash_keys(struct server_pool *sp, struct server *newsrv ) {
	struct server *server;
	char * keys_flag;
	uint32_t n_server, i, hash_count;
	int j;

	char  flag_status_1 = 0x1; //B01
	char  flag_status_2 = 0x2; //B10

	/*
	 * flag_status_1 = 0x01
	 * flag_status_2 = 0x10
	 * */

	keys_flag = nc_alloc(sizeof(char) * MODHASH_TOTAL_KEY);
	if (! keys_flag) {
		return NC_ERROR;
	}

	memset(keys_flag, '0', sizeof(char) * MODHASH_TOTAL_KEY);

	n_server = array_n(&sp->server);
	hash_count = 0;

	for (i = 0; i < n_server; i++) {
		server = array_get(&sp->server, i);
		if (server->status == SERVER_STATUS_NOTRANS) {
			for (j = server->seg_start; j <= server->seg_end; j++) {
				if (!(keys_flag[j] & flag_status_1) && j < MODHASH_TOTAL_KEY) {
					keys_flag[j] |= flag_status_1;
					hash_count++;
					//will occur a bus error if a printf
				} else {
					// more than 1 key slot status is 1. or the j is bigger than MODHASH_TOTAL_KEY
					log_error("error: hash key '%d' has more than one server in status 1!\n", j);
					goto err;
				}
			}
		} else if (server->status == SERVER_STATUS_TRANSING) {
			for (j = server->seg_start; j <= server->seg_end; j++) {
				if (!(keys_flag[j] & flag_status_2) && j < MODHASH_TOTAL_KEY) {
					keys_flag[j] |= flag_status_2;
					//will occur a bus error if a printf
				} else {
					// more than 1 key slot status is 1. or the j is bigger than MODHASH_TOTAL_KEY
					log_error("error: hash key '%d' has more than one server in status 1!\n", j);
					goto err;
				}
			}
		}

	}

	if (newsrv) {
		server = newsrv;
		for (j = server->seg_start; j <= server->seg_end; j++) {
			if (!(keys_flag[j] & flag_status_2) && j < MODHASH_TOTAL_KEY) {
				keys_flag[j] |= flag_status_2;
				//will occur a bus error if a printf
			} else {
				// more than 1 key slot status is 1. or the j is bigger than MODHASH_TOTAL_KEY
				log_error("error: hash key '%d' has more than one server in status 2!\n", j);
				goto err;
			}
		}

	}

	// not enogh slot status is 1!
	if (hash_count != MODHASH_TOTAL_KEY) {
		log_error("error: there are %d keys have no valid backends!", MODHASH_TOTAL_KEY - hash_count);

		//print 10 error key
		for (i = 0, j = 0; i < MODHASH_TOTAL_KEY; i++) {
			if (!(keys_flag[i] & flag_status_1)) {
				log_error("error: key '%d' has no valid backend.", i);
				j++;
			}
			if (j > 10)
				break;
		}
		goto err;
	}

	if (keys_flag) {
		free (keys_flag);
	}
	return NC_OK;

err:
	if (keys_flag) {
		free (keys_flag);
	}
	return NC_ERROR;

}


int server_pool_getkey_by_keyid(void *sp_p, char *sp_name, char *key_s, char * result) {
	int key, n;
	uint32_t n_sp, i;
	struct continuum *c;
	uint32_t svr_idx;
	struct server *svr, *newsvr;
	struct array *arr = sp_p;

	ASSERT(sp_p);
	n_sp = array_n(arr);

	for (i = 0; i < n_sp; i++) {
		struct server_pool *sp = array_get(arr, i);

		//find the sp_name
		if (!strcmp(sp_name, (const char *) sp->name.data)) {
			key = nc_atoi(key_s, strlen(key_s));
			if (key < 0 || key >= MODHASH_TOTAL_KEY) {
				nc_snprintf(result, 1024, "invalid key range [0~%d]", MODHASH_TOTAL_KEY-1);
				return NC_ERROR;
			}
			c = sp->continuum + key;

			//get the server index
			svr_idx = c->index;
			svr = array_get(&sp->server, svr_idx);

			if (c->status == CONTINUUM_STATUS_TRANSING) {
				newsvr = array_get(&sp->server, c->newindex);
				n = snprintf(result, 1024 , "bucket:%s status:%d oldserver:<%s> newserer:<%s>\n",key_s, c->status,  (char *)svr->pname.data, (char *)newsvr->pname.data);
			} else {
				n = snprintf(result, 1024, "bucket:%s status:%d oldserver:<%s> newserer:NULL\n",key_s, c->status, (char *)svr->pname.data);
			}

			return NC_OK;
		}
	}

	snprintf(result, 1024, "cannot find server_pool name '%s'\n", sp_name);

	return NC_ERROR;
}

int nc_is_valid_instance(char *inst, char *ip, int * port){
    unsigned int ip_len,port_len;

    ip_len=0;

    while(ip_len < strlen(inst) && inst[ip_len] != ':') ip_len ++;

    port_len =0;
    while(ip_len+port_len+1 <strlen(inst) && inst[ip_len+port_len+1]!=':') port_len++;

    if(ip_len == 0 || port_len == 0 || ip_len >16){
        log_error(" %s not a valid instance (IP:PORT[:WEIGHT])\n",inst);
        return NC_ERROR;
    }

    // result
    nc_memcpy(ip,inst,ip_len);
    ip[ip_len] = '\0';
    *port = nc_atoi(inst+ip_len+1,port_len);

    if(*port <= 0){
        log_error(" %s contain an invalid port(IP:PORT[:WEIGHT])\n",inst);
        return NC_ERROR;
    }

    return NC_OK;
}



int nc_server_change_instance(void *sp_a, char *sp_name, char *old_instance, char *new_instance, char* result) {
	uint32_t n, m, i, j;
	struct array *arr = sp_a;
	int rt;
	struct string addr;

	char old_ip[20], new_ip[20];
	int old_port, new_port;
	uint32_t oldsvr_index, newsvr_index;
	bool is_oldsvr_exist = false;
	bool is_newsvr_exist = false;
	struct sockinfo *ski = NULL;
	char *new_name = NULL;
	char *new_pname = NULL;
	int change_server_num = 0;

	log_debug(LOG_VERB, " in nc_server_change_instance");

	n = array_n(arr);

	for (i = 0; i < n; i++) {
		struct server_pool *sp = array_get(arr, i);
		//in this server pool

		if (!strcmp(sp_name, (const char*) sp->name.data)) {
			m = array_n(&sp->server);

			//log_debug(LOG_VERB, "sp name: %s, old inst: %s, new inst:%s", sp_name, old_instance, new_instance);

			/* step1: precheck instance format */
			if (nc_is_valid_instance(old_instance, old_ip, &old_port) != NC_OK || nc_is_valid_instance(new_instance, new_ip, &new_port) != NC_OK) {
				log_error("invalid instance config, old instance: %s ,new instance:%s \n", old_instance, new_instance);
				snprintf(result, STATS_RESULT_BUFLEN, "invalid instance info, old instance: %s ,new instance:%s \n", old_instance, new_instance);
				return NC_ERROR;
			}

			//log_debug(LOG_VERB, "info: old: %s:%d, new: %s:%d\n", old_ip, old_port, new_ip, new_port);

			// return fail the  new instance  already exists
			struct server *svr;
			for (j = 0; j < m; j++) {
				svr = array_get(&sp->server, j);
				if (svr->status == 0)
					continue; //a no use server
				//check if the new server exist?

				if (       ( ! svr->reload_svr && !nc_strncmp(svr->name.data, new_instance, strlen(new_instance)))
						|| (svr->reload_svr && !nc_strncmp(svr->mif.new_name, new_instance, strlen(new_instance)))) {
					is_newsvr_exist = true;
					newsvr_index = j;
					snprintf(result, STATS_RESULT_BUFLEN, "server %s %s already exits in server pool %s\n", new_instance, svr->name.data, sp_name);
					return NC_ERROR;
				}
			}

			// check the old instance

			for (j = 0; j < m; j++) {
				svr = array_get(&sp->server, j);
				if (svr->status == 0)
					continue; //a no use server
				log_error("%s vs %s", svr->name.data, old_instance);
				//find the svr need to be replace
				if (!nc_strncmp(svr->name.data, old_instance, strlen(old_instance))
						|| (svr->reload_svr && !nc_strncmp(svr->mif.new_name, old_instance, strlen(old_instance)))) {

					is_oldsvr_exist = true;
					oldsvr_index = j;
					change_server_num++;
					log_debug(LOG_VERB, "start to change server");
					ASSERT(svr);

					/* sockinfo */

					ski = (void *) nc_alloc(sizeof(struct sockinfo));
					if (!ski) {
						return NC_ENOMEM;
					}

					new_name = (void *) nc_alloc(1024);
					if (!new_name) {
						nc_free(ski);
						return NC_ENOMEM;
					}

					new_pname = (void *) nc_alloc(1024);
					if (!new_pname) {
						nc_free(ski);
						nc_free(new_name);
						return NC_ENOMEM;
					}

					snprintf(new_pname, STATS_RESULT_BUFLEN, "%s:1 %s %d-%d %d", new_instance, svr->app.data, svr->seg_start, svr->seg_end, svr->status);
					snprintf(new_name, STATS_RESULT_BUFLEN, "%s:%d", new_ip, new_port);

					string_init(&addr);
					rt = string_copy(&addr, (uint8_t *) new_ip, (uint32_t) strlen(new_ip));
					if (rt != NC_OK) {
						goto err;
					}

					rt = nc_resolve(&addr, new_port, ski);
					if (rt != NC_OK) {
						goto err;
					}
					/* step 1 change file*/
					sp_write_conf_file(sp, i, (int) j, new_pname);

					/* save new backend information for main thread to modify, thread lock for safe */
					pthread_mutex_lock(&svr->mutex);

					// step 2: modify the meminfo,and change the reload_svr flag for loading new config
					if (svr->reload_svr) { /* modify the instance info,but the old modification has not reload,free the svr->mif */
						log_error ("do free svr->mif\n");
						nc_free(svr->mif.ski);
						nc_free(svr->mif.new_name);
						nc_free(svr->mif.new_pname);
					} /* else: the prev modification has reload,need not to free the old mif info */

					svr->mif.ski = ski;
					svr->mif.new_name = new_name;
					svr->mif.new_pname = new_pname;
					svr->reload_svr = true;

					stats_pool_change_server_name(sp, j, svr->mif.new_name);

					pthread_mutex_unlock(&svr->mutex);

				}



			}

			if (change_server_num > 0) {
				snprintf(result, STATS_RESULT_BUFLEN, "change %d banckends from ' %s ' to  ' %s ' success.\n", change_server_num, old_instance, new_instance);
				return NC_OK;
			} else   {
				snprintf(result, STATS_RESULT_BUFLEN, "cannot find svr %s in server pool %s\n", old_instance, sp_name);
				return NC_ERROR;
			}

		}
	}

	// not found the config
	if (!is_oldsvr_exist) {
		snprintf(result, STATS_RESULT_BUFLEN, "cannot find svr %s in server pool %s\n", old_instance, sp_name);
	} else {
		snprintf(result, STATS_RESULT_BUFLEN, "cannot find redis pool %s\n", sp_name);
	}
	err: if (ski) {
		nc_free(ski);
	}
	if (new_name) {
		nc_free(new_name);
	}
	if (new_name) {
		nc_free(new_pname);
	}

	snprintf(result, STATS_RESULT_BUFLEN, "change svrver failed\n");
	return NC_ERROR;

}


// here we create a vitual client_conn to send auth info
rstatus_t server_send_redis_auth(struct context *ctx, struct conn *s_conn){
    struct server_pool *sp;
    int n;

    rstatus_t status;

    char auth_str[1024];
  //  char auth_recv[1024];


    sp = ((struct server*)s_conn->owner)->owner;
    ASSERT(sp);

    if( ! sp->b_redis_pass ){
        log_debug(LOG_VERB, "No redis password set, skip authentication. ");
        return NC_OK;
    }

    ASSERT(!string_empty(&sp->redis_password));

    // concat the auth command
    nc_snprintf(auth_str,1024,"*2"CRLF"$4"CRLF"auth"CRLF"$%d"CRLF"%s"CRLF,sp->redis_password.len,sp->redis_password.data);

    //  make a new auth packet to send to server.

    struct msg *au_msg= msg_get(s_conn, true, s_conn->redis);
    struct mbuf *mbuf;
    size_t msize;
    mbuf = STAILQ_LAST(&au_msg->mhdr, mbuf, next);
    if( mbuf == NULL || mbuf_full(mbuf)){
        mbuf = mbuf_get();
        if( mbuf == NULL){
            return NC_ENOMEM;
        }   

        mbuf_insert(&au_msg->mhdr, mbuf);
        au_msg->pos = mbuf->pos;
    }

    ASSERT(mbuf->end - mbuf->last > 0); 
    msize = mbuf_size(mbuf);

    n =nc_snprintf(mbuf->last,1024,"*2"CRLF"$4"CRLF"auth"CRLF"$%d"CRLF"%s"CRLF,sp->redis_password.len,sp->redis_password.data);

    ASSERT(mbuf->last + n <= mbuf->end);
    mbuf->last += n;
    au_msg->mlen += (uint32_t)n;

    au_msg->owner = NULL;
    au_msg->swallow = 1;


    s_conn->enqueue_inq(ctx, s_conn, au_msg);

    status = event_add_in(ctx->evb, s_conn);
    if (status != NC_OK) {
    	//return t; ?
    }
    return NC_OK;
}

