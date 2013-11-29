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

static rstatus_t server_set_new_owner(void * elem, void *data);

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

    null_config
};


/* copy server to another */
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
    ASSERT(nserver != 0);
    ASSERT(array_n(server) == 0);

    status = array_init(server, nserver, sizeof(struct server));
    if (status != NC_OK) {
        return status;
    }

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
        log_warn("connect to server '%.*s' failed, ignored: %s",
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
                  conn->sd,  server->pname.len, server->pname.data,
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
            //return NC_OK;
            printf("EINPROGRESS\n");
            goto con_ok;
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
    log_debug(LOG_VERB, "connect to server %s\n\n\n",server->pname.data);

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

static uint32_t
server_pool_hash(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    ASSERT(array_n(&pool->server) != 0);

    if (array_n(&pool->server) == 1) {
        return 0;
    }

    ASSERT(key != NULL && keylen != 0);

    return pool->key_hash((char *)key, keylen);
}

static struct server *
server_pool_server(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    struct server *server;
    uint32_t hash, idx;

    ASSERT(array_n(&pool->server) != 0);
    ASSERT(key != NULL && keylen != 0);

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
        idx = modhash_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    default:
        NOT_REACHED();
        return NULL;
    }
    ASSERT(idx < array_n(&pool->server));

    server = array_get(&pool->server, idx);

    log_debug(LOG_VERB, "key '%.*s' on dist %d maps to server '%.*s'", keylen,
              key, pool->dist_type, server->pname.len, server->pname.data);

    return server;
}

struct conn *
server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key,
                 uint32_t keylen)
{
    rstatus_t status;
    struct server *server;
    struct conn *conn;

    status = server_pool_update(pool);
    if (status != NC_OK) {
        return NULL;
    }

    /* from a given {key, keylen} pick a server from pool */
    server = server_pool_server(pool, key, keylen);
    if (server == NULL) {
        return NULL;
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
            server->pname.len  = (size_t)nc_strlen(server->mif.new_pname);
            server->name.data = (uint8_t*)server->mif.new_name;
            server->name.len  = (size_t)strlen(server->mif.new_name);

            struct server_pool *tpool= server->owner;
            while(!TAILQ_EMPTY(&server->s_conn_q)){
                ASSERT(server->ns_conn_q > 0 );

                conn = TAILQ_FIRST(&server->s_conn_q);
                conn->close(tpool->ctx, conn);
            }

            /* reload OK */
            server->reload_svr = false;
        }
        
        pthread_mutex_unlock(&server->mutex);
    }


    /* pick a connection to a given server */
    conn = server_conn(server);
    if (conn == NULL) {
        return NULL;
    }

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

rstatus_t
server_pool_run(struct server_pool *pool)
{
    ASSERT(array_n(&pool->server) != 0);

    switch (pool->dist_type) {
    case DIST_KETAMA:
        return ketama_update(pool);

    case DIST_MODULA:
        return modula_update(pool);

    case DIST_RANDOM:
        return random_update(pool);

    case DIST_MODHASH:
        return modhash_update(pool);

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



int sp_get_server( struct server_pool *sp, struct sp_config *spc, char * result){
    uint8_t *p;
    struct array *arr= NULL; 
    uint32_t svr_num=0,i;
    char *strp;

    p = (void *)sp; 
    arr = (struct array *)(p + spc->offset);
    svr_num = array_n(arr);
        
    strp = result;
        
    for (i = 0; i < svr_num; i++) {
        struct server *cs = array_get(arr, i);


        // add thread lock for safe
        pthread_mutex_lock(&cs->mutex);

        if(cs->reload_svr){
            snprintf(strp, 1024,"%s %s %d-%d %d\n",cs->mif.new_name,cs->app.data,cs->seg_start,cs->seg_end,cs->status);
        }else{
            snprintf(strp, 1024,"%s %s %d-%d %d\n",cs->name.data,cs->app.data,cs->seg_start,cs->seg_end,cs->status);
        }
        pthread_mutex_unlock(&cs->mutex);

        strp = result+strlen(result);
    }

    return NC_OK;
}


int sp_get_by_item(char *sp_name, char *sp_item ,char *result, void *sp){
        uint32_t n,m,i;
        struct array *arr = sp;
        int rt;

        struct string item;
        item.data = (void *)sp_item;
        item.len = (size_t)nc_strlen(sp_item);

        n = array_n(arr);

        //printf("ctx->stats->p_cf element num: %d\n",n);
        for(i=0;i<n;i++){
                struct server_pool *tcf = array_get(arr,i);
                //printf("sname: %s\n",tcf->name.data);
                //in this server pool
                if(!strcmp(sp_name, tcf->name.data)){
                         m = array_n(&tcf->server);
                        /*for(j=0;j<m;j++){
                                struct server *tss = array_get(&tcf->server,j);
                                printf("%d name : %s\n",j,tss->name.data);
                        } */

                        rt = server_pool_get_config_by_string(tcf, &item, result);
                        if( rt != NC_OK){
                            log_error("get config by string fail: %s\n",sp_item );
                            snprintf(result,80,"get config by string fail: %s\n",sp_item );
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

int nc_add_a_server(void *sp, char *sp_name, char *inst, char* app, char *seqs, char *status,char *result){
    uint32_t n,m,i;
    struct array *arr = sp;
    int rt;
    struct string item;

    log_debug(LOG_VERB, " in nc_add_a_server");

    item.data= inst;
    item.len = (size_t) nc_strlen(inst);

    n = array_n(arr);

    for(i=0;i<n;i++){
        struct server_pool *tcf = array_get(arr,i);
        //in this server pool
        if(!strcmp(sp_name, tcf->name.data)){
            m = array_n(&tcf->server);
            /*for(j=0;j<m;j++){
                struct server *tss = array_get(&tcf->server,j);
                printf("%d name : %s\n",j,tss->name.data);
            } */
            log_debug(LOG_VERB,"sp name: %s, inst: %s, app:%s, seqs: %s, status: %s\n", sp_name,inst,app,seqs,status);

            /* step1: precheck  */
            rt = nc_add_new_server_precheck(tcf,inst,app,seqs,status,result);

            if( rt != NC_OK){
                log_error("new add server precheck failed: %s\n",sp_name);
                return NC_ERROR;
            }

            return NC_OK;

        }
    }

    // not found the config
    snprintf(result,80,"cannot find redis pool %s\n",sp_name );
    return NC_ERROR;

}

/* precheck for adding a server to a server_pool */
int nc_add_new_server_precheck( struct server_pool *sp, char * inst, char * app, char * seqs, char* status, char* result){
    struct string sp_app;
    struct array *arr     = &sp->server;
    struct array new_servers;
    struct array *new_svrs, *old_svrs;
    struct server *svr, *new_svr;

    uint32_t n_old_svrs = array_n(arr);
    uint32_t n_new_svrs = n_old_svrs + 1;
    int port,seg_start,seg_end,istatus, i;
    size_t ip_len,port_len,seg_start_len;
    struct sockinfo *ski;
    rstatus_t ret;

    struct string addr;

    //get the first server info
    svr = array_get(arr,0);
    sp_app = svr->app;

    // app is different
    if(strcmp(app,sp_app.data)){
        snprintf(result,1000,"new add app '%s' is different from app in server pool '%s' \n",app,sp_app.data);
        return NC_ERROR;
    }


    ip_len=0;

    while(ip_len < nc_strlen(inst) && inst[ip_len] != ':') ip_len ++;

    port_len =0;
    while(ip_len+port_len+1 <strlen(inst) && inst[ip_len+port_len+1]!=':') port_len++;

    if(ip_len == 0 || port_len == 0){
        snprintf(result,1000," %s not a valid instance (IP:PORT[:WEIGHT])\n",inst);
        return NC_ERROR;
    }

    port = nc_atoi(inst+ip_len+1,port_len);
    
    seg_start_len=0;
    while(seg_start_len < strlen(seqs) && seqs[seg_start_len] != '-') seg_start_len++;

    if(seg_start_len == strlen(seqs)){
        seg_start = seg_end = nc_atoi(seqs ,seg_start_len);
    }else{
        seg_start = nc_atoi(seqs ,seg_start_len);
        seg_end   = nc_atoi(seqs+seg_start_len+1,strlen(seqs)-seg_start_len-1);
    }

    istatus = nc_atoi(status,1);

    if(port <0 || seg_start<0 || seg_end<0 || istatus<0){
        snprintf(result,1000," config error: %s %s %s %s\n",inst,app,seqs,status);
        return NC_ERROR;
    }

    if(seg_start > seg_end){
        snprintf(result,1000,"seg_start cannot bigger than seg_end,start: %d, end: %d\n",seg_start,seg_end);
        return NC_ERROR;
    }


    /* precheck ok,start to add new server */
    //snprintf(result,1000,"check ok. svrapp:%s, app: %s ,iplen: %.*s port_len: %.*s . seqstart:%d ,seqend:%d ,status:%d\n",sp_app.data,app,ip_len,inst,port_len,inst+ip_len+1,seg_start,seg_end,istatus);

    // init new servers
    array_null(&new_servers);
    new_svrs = &new_servers;

    // allocate new mem
    ret = array_init(new_svrs, n_new_svrs, sizeof(struct server));
    if(ret != NC_OK){
        return NC_ERROR;
    }

    for(i = 0; i < n_old_svrs; i++){
        svr     = array_get(arr,i);
        new_svr = array_push(new_svrs);
        nc_memcpy( new_svr, svr, new_svrs->size);
    }
    // init the new added svr info
    new_svr = array_push(new_svrs);

    ASSERT(new_svr);
    
    new_svr->idx = array_idx(new_svrs, new_svr);
    new_svr->owner = sp;

    string_init(&new_svr->pname);
    ret = string_copy(&new_svr->pname, inst, strlen(inst));
    if(ret != NC_OK){
        return NC_ERROR;
    }

    string_init(&new_svr->name);
    ret = string_copy(&new_svr->name , inst, strlen(inst));
    if(ret != NC_OK){
        return NC_ERROR;
    }

    new_svr->port  = port;
    new_svr->weight= 1;

    /* sockinfo */
    ski = (void *)nc_alloc(sizeof(struct sockinfo));
    if( !ski){
        return NC_ERROR;
    }

    string_init(&addr);
    ret = string_copy(&addr, inst, ip_len);
    if(ret != NC_OK){
        return ret;
    }

    ret = nc_resolve(&addr, port, ski);
    if(ret != NC_OK){
        return ret;
    }

    new_svr->family = ski->family;
    new_svr->addrlen= ski->addrlen;
    new_svr->addr   = (struct sockaddr*)&ski->addr;

    /* app */
    string_init(&new_svr->app);
    string_copy(&new_svr->app,app,strlen(app));
    new_svr->seg_start = seg_start;
    new_svr->seg_end   = seg_end;
    new_svr->status    = istatus;

    new_svr->ns_conn_q = 0;
    TAILQ_INIT(&new_svr->s_conn_q);

    new_svr->next_retry = 0LL;
    new_svr->failure_count = 0;

    if (ret != NC_OK) {
        return ret;
    }

    old_svrs = &sp->server;

    // if the old sp is modified, deinit the server ,or set the is_modified flag to 1
    if(sp->is_modified){

        old_svrs->nelem = new_svrs->nelem;
        old_svrs->size  = new_svrs->size;
        old_svrs->elem  = new_svrs->elem;
        old_svrs->nalloc= new_svrs->nalloc;

        log_debug(LOG_DEBUG, "deinit old server info");
    }else{ 

        old_svrs->nelem = new_svrs->nelem;
        old_svrs->size  = new_svrs->size;
        old_svrs->elem  = new_svrs->elem;
        old_svrs->nalloc= new_svrs->nalloc;

        sp->is_modified = 1;
        log_debug(LOG_DEBUG, "set is_modified flag to 1");
    }

    array_each(&sp->server,server_set_new_owner,NULL);

    //snprintf(result,1000,"add server OK. svrapp:%s, app: %s ,iplen: %.*s port_len: %.*s . seqstart:%d ,seqend:%d ,status:%d\n",sp_app.data,app,ip_len,inst,port_len,inst+ip_len+1,seg_start,seg_end,istatus);
    return NC_OK;
}

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

rstatus_t server_check_hash_keys( struct server_pool *sp){
    struct server *server;
    bool keys_flag[MODHASH_TOTAL_KEY];
    uint32_t n_server, i, j, hash_count;

    memset(keys_flag, 0, sizeof(keys_flag));

    n_server = array_n(&sp->server);
    hash_count = 0;

    for(i = 0; i< n_server; i++){
        server = array_get(&sp->server, i);
        if(server->status < 1)
            continue;

        for(j = server->seg_start; j<= server->seg_end; j++){
            if(keys_flag[j] == 0 && j< MODHASH_TOTAL_KEY ){
                keys_flag[j] = 1;
                hash_count ++;
            }else{
                // more than 1 key slot status is 1. or the j is bigger than MODHASH_TOTAL_KEY
                log_error("error: hash key '%d' has more than one status is 1!\n",j);
                return NC_ERROR;
            }
        }

    }

    // not enogh slot status is 1!
    if(hash_count != MODHASH_TOTAL_KEY){
        log_error("error: there are %d keys have no valid backends!\n",MODHASH_TOTAL_KEY - hash_count);

        //print 10 error key
        for(i=0, j=0; i< MODHASH_TOTAL_KEY; i++){
            if(keys_flag[i] == 0){
                log_error("error: key '%d' has no valid backend.\n",i);
                j++;
            }
            if(j>10)
                break;
        }
        return NC_ERROR;
    }

    return NC_OK;
}


int server_pool_getkey_by_keyid(void *sp_p,char *sp_name, char *key_s, char * result){
    uint32_t key, n_sp, i;
    struct continuum *c;
    uint32_t svr_idx;
    struct server *svr;
    struct array *arr = sp_p;

    ASSERT(sp_p);
    n_sp = array_n(arr);
    
    for(i = 0; i< n_sp; i++){
        struct server_pool *sp = array_get(arr, i);

        //find the sp_name
        if(!strcmp(sp_name, sp->name.data)){
            key = nc_atoi(key_s, strlen(key_s));
            if( key <0 || key >= MODHASH_TOTAL_KEY)
            {
                nc_snprintf(result,1024,"invalid key range [0~%d]",MODHASH_TOTAL_KEY-1);
                return NC_ERROR;
            }
            c = sp->continuum + key;

            //get the server index
            svr_idx = c->index;

            //get the server
            svr = array_get(&sp->server, svr_idx);

            snprintf(result,1024,"%s\n",svr->pname.data);
            return NC_OK;
        }
    }

    snprintf(result,1024,"cannot find server_pool name '%s'\n",sp_name);

    return NC_ERROR;
}

int nc_is_valid_instance(char *inst, char *ip, int * port){
    int ip_len,port_len;

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
    *port = nc_atoi(inst+ip_len+1,port_len);

    if(*port <= 0){
        log_error(" %s contain an invalid port(IP:PORT[:WEIGHT])\n",inst);
        return NC_ERROR;
    }

    return NC_OK;
}

int nc_server_change_instance(void *sp_a, char *sp_name, char *old_instance, char *new_instance, char* result){
    uint32_t n,m,i,j;
    struct array *arr = sp_a;
    int rt;
    struct string addr;

    char old_ip[20],new_ip[20];
    int  old_port,new_port, oldsvr_index;
    bool is_oldsvr_exist = false;
    struct sockinfo *ski ;
    char            *new_name;
    char            *new_pname;

    log_debug(LOG_VERB, " in nc_server_change_instance");

    n = array_n(arr);

    for(i=0;i<n;i++){
        struct server_pool *sp= array_get(arr,i);
        //in this server pool
        if(!strcmp(sp_name, sp->name.data)){
            m = array_n(&sp->server);

            log_debug(LOG_VERB,"sp name: %s, old inst: %s, new inst:%s \n", sp_name,old_instance, new_instance);

            /* step1: precheck instance format */
            if(nc_is_valid_instance(old_instance, old_ip, &old_port) != NC_OK || 
                    nc_is_valid_instance(new_instance, new_ip, &new_port) != NC_OK){
                log_error("invalid instance config, old instance: %s ,new instance:%s \n",old_instance, new_instance);
                snprintf(result,1024,"invalid instance info, old instance: %s ,new instance:%s \n",old_instance, new_instance);
                return NC_ERROR;
            }

            log_debug(LOG_VERB,"info: old: %s:%d, new: %s:%d\n", old_ip, old_port, new_ip, new_port );

            //TODO: add new server here
            rt = NC_OK;

            if( rt != NC_OK){
                log_error("new add server precheck failed: %s\n",sp_name);
                return NC_ERROR;
            }

            // check the old instance
            struct server *svr;
            for( j=0; j<m; j++){
                svr = array_get(&sp->server, j);

                //find the svr need to be replace
                if(! nc_strncmp( svr->name.data, old_instance, strlen(old_instance)) || 
                        (svr->reload_svr && !nc_strncmp( svr->mif.new_name, old_instance, strlen(old_instance)))){
                    is_oldsvr_exist = true;
                    oldsvr_index = j;
                    break;
                }
            }

            if( !is_oldsvr_exist){
                snprintf(result,80,"cannot find svr %s in server pool %s\n",old_instance, sp_name );
                return NC_ERROR;
            }

            log_debug(LOG_VERB,"check ok, start to change.\n");
            ASSERT(svr);

            // first change the content of svr, then close all the connections of svr
            //
            /* sockinfo */

            ski = (void *)nc_alloc(sizeof(struct sockinfo));
            if( !ski){
                return NC_ENOMEM;
            }

            new_name = (void *) nc_alloc(1024);
            if( !new_name ){
                nc_free(ski);
                return NC_ENOMEM;
            }

            new_pname = (void *) nc_alloc(1024);
            if( !new_pname ){
                nc_free(ski);
                nc_free(new_name);
                return NC_ENOMEM;
            }


            snprintf(new_pname,1024,"%s:1 %s %d-%d %d",new_instance, svr->app.data, svr->seg_start, svr->seg_end, svr->status);
            snprintf(new_name,1024,"%s:%d",new_ip,new_port );

            string_init(&addr);
            rt = string_copy(&addr, new_ip, strlen(new_ip));
            if(rt != NC_OK){
                goto err;
            }

            rt = nc_resolve(&addr, new_port, ski);
            if(rt != NC_OK){
                goto err;
            }

            // step 1: first write new config file

            sp_write_conf_file(sp, i, j, new_pname);


            // step 2: modify the meminfo,and change the reload_svr flag for loading new config
            /* save new backend information for main thread to modify, thread lock for safe */
            pthread_mutex_lock(&svr->mutex);

            if( svr->reload_svr){  /* modify the instance info,but the old modification has not reload,free the svr->mif */
                nc_free(svr->mif.ski);
                nc_free(svr->mif.new_name);
                nc_free(svr->mif.new_pname);
            }  /* else: the prev modification has reload,need not to free the old mif info */

            svr->mif.ski = ski;
            svr->mif.new_name = new_name;
            svr->mif.new_pname= new_pname;
            svr->reload_svr = true;

            pthread_mutex_unlock(&svr->mutex);

            snprintf(result, 1024, "change banckends from ' %s ' to  ' %s ' success.\n",old_instance, new_instance);
            return NC_OK;

        }
    }

    // not found the config
    if( !is_oldsvr_exist){
        snprintf(result,80,"cannot find svr %s in server pool %s\n",old_instance, sp_name );
    }else{
        snprintf(result,80,"cannot find redis pool %s\n",sp_name );
    }
err:
    if(ski)
    {
        nc_free(ski);
    }
    if(new_name)
    {
        nc_free(new_name);
    }
    if(new_name)
    {
        nc_free(new_pname);
    }
    return NC_ERROR;

}


// here we create a vitual client_conn to send auth info
rstatus_t server_send_redis_auth(struct context *ctx, struct conn *s_conn){
    struct server_pool *sp;
    int n;

    rstatus_t status;

    char auth_str[1024];
    char auth_recv[1024];


    sp = ((struct server*)s_conn->owner)->owner;
    ASSERT(sp);

    if( ! sp->b_redis_pass ){
        log_debug(LOG_VERB, "No redis password set, skip authentication. ");
        return NC_OK;
    }

    ASSERT(!string_empty(&sp->redis_password));

    // concat the auth command
    nc_snprintf(auth_str,1024,"*2"CRLF"$4"CRLF"auth"CRLF"$%d"CRLF"%s"CRLF,sp->redis_password.len,sp->redis_password.data);

    status = nc_set_blocking(s_conn->sd);
    if (status != NC_OK) {
        log_error("set block on s %d for server on auth step  failed: %s",
                  s_conn->sd, strerror(errno));
        return NC_ERROR;
    }

    //send auth 
    n = nc_write(s_conn->sd,auth_str,nc_strlen(auth_str));

    if(n<0 ){
        nc_set_nonblocking(s_conn->sd);
        return NC_ERROR;
    }
    log_debug(LOG_VERB, "send server return:%s %d.\n\n",auth_str,n);


    // receive the auth result
    for(;;){
        n = nc_read(s_conn->sd, auth_recv, 1024);
        if(n>=0){
            break;
        }

        if(errno == EINTR || errno == EAGAIN){
            continue;
        }
        else{
            log_error("recv on sd %d failed: err info: %d %s",s_conn->sd,errno, strerror(errno));
            return NC_ERROR;
        }
    }

    // auth returna, set s_conn as noblocking
    status = nc_set_nonblocking(s_conn->sd);

    if (status != NC_OK) {
        log_error("set nonblock on s %d for server on auth step  failed: %s",
                  s_conn->sd, strerror(errno));
        return NC_ERROR;
    }

    log_debug(LOG_VERB, "redis server return:%s %d.\n\n",auth_recv,n);

    // redis authentication pass
    if(!nc_strncmp(auth_recv,"+OK", 3)){
        log_debug(LOG_VERB, "redis authentication OK.");
        s_conn-> authed = 1;
    }else if(!nc_strncmp(auth_recv,"-ERR invalid password"CRLF, nc_strlen(auth_recv))){
        log_debug(LOG_VERB, "redis authentication failed:  invalid password.");
    }else if(!nc_strncmp(auth_recv,"-ERR Client sent AUTH, but no password is set"CRLF,nc_strlen(auth_recv))){
        log_warn("redis authentication warn: %s", auth_recv);
    }else{
        log_debug(LOG_VERB, "redis authentication failed: ret:%s ",auth_recv);
    }

    return NC_OK;
}
