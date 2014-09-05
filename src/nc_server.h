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

#ifndef _NC_SERVER_H_
#define _NC_SERVER_H_

#include <nc_core.h>

/*
 * server_pool is a collection of servers and their continuum. Each
 * server_pool is the owner of a single proxy connection and one or
 * more client connections. server_pool itself is owned by the current
 * context.
 *
 * Each server is the owner of one or more server connections. server
 * itself is owned by the server_pool.
 *
 *  +-------------+
 *  |             |<---------------------+
 *  |             |<------------+        |
 *  |             |     +-------+--+-----+----+--------------+
 *  |   pool 0    |+--->|          |          |              |
 *  |             |     | server 0 | server 1 | ...     ...  |
 *  |             |     |          |          |              |--+
 *  |             |     +----------+----------+--------------+  |
 *  +-------------+                                             //
 *  |             |
 *  |             |
 *  |             |
 *  |   pool 1    |
 *  |             |
 *  |             |
 *  |             |
 *  +-------------+
 *  |             |
 *  |             |
 *  .             .
 *  .    ...      .
 *  .             .
 *  |             |
 *  |             |
 *  +-------------+
 *            |
 *            |
 *            //
 */

typedef uint32_t (*hash_t)(const char *, size_t);

#define MODHASH_TOTAL_KEY  420000      /* total hash keys: 42w */

#define SERVER_STATUS_NOTRANS  1   /* return old */
#define SERVER_STATUS_TRANSING 2   /* return old, try to redirect to new */
#define SERVER_STATUS_TRANSED  3   /* return new */

#define CONTINUUM_STATUS_NOTRANS  1   /* return old */
#define CONTINUUM_STATUS_TRANSING 2   /* return old, try to redirect to new */
#define CONTINUUM_STATUS_TRANSED  3   /* return new */

struct continuum {
    uint32_t index;  /* server index */
    uint32_t value;  /* hash value */
    uint32_t newindex;  /* new server index, default -1 */
    unsigned  status:2; /* transfer_status: 0:old; 1,old,new; 2:new*/

};



struct modify_info{
    struct sockinfo *ski;
    char            *new_name;
    char            *new_pname;
};

struct server {
    uint32_t           idx;           /* server index */
    struct server_pool *owner;        /* owner pool */

    struct string      pname;         /* name:port:weight (ref in conf_server) */
    struct string      name;          /* name (ref in conf_server) */
    uint16_t           port;          /* port */
    uint32_t           weight;        /* weight */
    int                family;        /* socket family */
    socklen_t          addrlen;       /* socket length */
    struct sockaddr    *addr;         /* socket address (ref in conf_server) */

    struct string      app;     /* app info */
    int                status;  /* instance status */
    int                seg_start; /* start of segment */
    int                seg_end  ; /* start of segment */
    bool               sock_need_free; /* if need to free the sock addr */
    struct sockinfo    *sock_info;    /* pointer to the sock info*/
    struct modify_info mif;           /* struct for store modify information when modify the config */
    bool               reload_svr;    /* flag to check if need to reload svr info from modify_info above */
    pthread_mutex_t    mutex;         /* mutex for modify config infomation */

    uint32_t           ns_conn_q;     /* # server connection */
    struct conn_tqh    s_conn_q;      /* server connection q */

    int64_t            next_retry;    /* next retry time in usec */
    uint32_t           failure_count; /* # consecutive failures */
};

struct server_pool {
    uint32_t           idx;                  /* pool index */
    struct context     *ctx;                 /* owner context */

    struct conn        *p_conn;              /* proxy connection (listener) */
    uint32_t           nc_conn_q;            /* # client connection */
    struct conn_tqh    c_conn_q;             /* client connection q */

    struct array       server;               /* server[] */
    int                is_modified;          /* if set to 1, the server info is reallocated */

    uint32_t           ntrans_continuum  ;  /* # continuum points in transfer status*/
    uint32_t           ncontinuum;           /* # continuum points */
    uint32_t           nserver_continuum;    /* # servers - live and dead on continuum (const) */
    struct continuum   *continuum;           /* continuum */
    uint32_t           nlive_server;         /* # live server */
    int64_t            next_rebuild;         /* next distribution rebuild time in usec */

    struct string      name;                 /* pool name (ref in conf_pool) */
    struct string      password;             /* pool password */
    struct string      redis_password;       /* pool password for access redis backends */
    struct string      addrstr;              /* pool address (ref in conf_pool) */
    uint16_t           port;                 /* port */
    int                family;               /* socket family */
    socklen_t          addrlen;              /* socket length */
    struct sockaddr    *addr;                /* socket address (ref in conf_pool) */
    int                dist_type;            /* distribution type (dist_type_t) */
    int                key_hash_type;        /* key hash type (hash_type_t) */
    hash_t             key_hash;             /* key hasher */
    struct string      hash_tag;             /* key hash tag (ref in conf_pool) */
    int                timeout;              /* timeout in msec */
    int                backlog;              /* listen backlog */
    uint32_t           client_connections;   /* maximum # client connection */
    uint32_t           server_connections;   /* maximum # server connection */
    int64_t            server_retry_timeout; /* server retry timeout in usec */
    uint32_t           server_failure_limit; /* server failure limit */
    unsigned           auto_eject_hosts:1;   /* auto_eject_hosts? */
    unsigned           preconnect:1;         /* preconnect? */
    unsigned           redis:1;              /* redis? */

    unsigned           b_pass:1;             /* if access twemproxy need password? */
    unsigned           b_redis_pass:1;       /* if access backends redis servers need password? */
    unsigned           status:2;             /* 0:nouse, 1:notrans ,2:transing, 3:trans done */
};

void server_ref(struct conn *conn, void *owner);
void server_unref(struct conn *conn);
int server_timeout(struct conn *conn);
bool server_active(struct conn *conn);
rstatus_t server_init(struct array *server, struct array *conf_server, struct server_pool *sp);
void server_deinit(struct array *server);
struct conn *server_conn(struct server *server);
rstatus_t server_connect(struct context *ctx, struct server *server, struct conn *conn);
void server_close(struct context *ctx, struct conn *conn);
void server_connected(struct context *ctx, struct conn *conn);
void server_ok(struct context *ctx, struct conn *conn);

struct conn *server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key, uint32_t keylen, struct msg *msg);
rstatus_t server_pool_run(struct server_pool *pool);
rstatus_t server_pool_preconnect(struct context *ctx);
void server_pool_disconnect(struct context *ctx);
rstatus_t server_pool_init(struct array *server_pool, struct array *conf_pool, struct context *ctx);
void server_pool_deinit(struct array *server_pool);
struct server * server_pool_server(struct server_pool *pool, uint8_t *key, uint32_t keylen, bool redirect);



struct sp_config{
    struct string name;
    int   (*get)(struct server_pool *sp, struct sp_config *spc, char *data);
    int    offset;
};


int sp_get_server( struct server_pool *sp, struct sp_config *spc, char * result);

int sp_get_by_item(char *sp_name, char *sp_item ,char *result, void *sp);
#define null_config { null_string, NULL, 0 }


int server_pool_get_config_by_string(struct server_pool *sp, struct string *item, char * result);
int server_pool_getkey_by_keyid(void *sp_p, char *sp_name, char* key, char * result);

/* send the auth package to redis server */
rstatus_t server_send_redis_auth(struct context *ctx, struct conn *s_conn);

/* a wrapper of req_forward */
void req_redirect (struct context *ctx, struct conn *c_conn, struct msg *msg);

/* 
 * parameters:
 * sp: server_pool array
 * sp_name: server pool name
 * inst: redis instance in format of IP:PORT
 * app : app  name
 * seqs: hash sequence of START-END
 * status: 0 or 1
 * */
int nc_add_a_server(void *sp, char *sp_name, char *inst, char* app, char *seqs, char *status,char *result);
rstatus_t server_check_hash_keys( struct server_pool *sp);

int nc_server_change_instance(void *sp, char *sp_name, char *old_instance,char *new_instance, char* result);

int nc_add_new_server_precheck( struct server_pool *sp, char * inst, char * app, char * seqs, char* status, char* result);
int nc_is_valid_instance(char *inst, char *ip, int * port);
#endif
