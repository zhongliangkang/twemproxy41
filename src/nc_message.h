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

#ifndef _NC_MESSAGE_H_
#define _NC_MESSAGE_H_

#include <nc_core.h>

typedef void (*msg_parse_t)(struct msg *);
typedef rstatus_t (*msg_fragment_t)(struct msg *, uint32_t, struct msg_tqh *);
typedef void (*msg_coalesce_t)(struct msg *r);
typedef rstatus_t (*msg_reply_t)(struct msg *r);

typedef enum msg_parse_result {
    MSG_PARSE_OK,                         /* parsing ok */
    MSG_PARSE_ERROR,                      /* parsing error */
    MSG_PARSE_REPAIR,                     /* more to parse -> repair parsed & unparsed data */
    MSG_PARSE_FRAGMENT,                   /* multi-vector request -> fragment */
    MSG_PARSE_AGAIN,                      /* incomplete -> parse again */
    MSG_PARSE_AUTH,                       /* auth  -> request for auth */
    MSG_PARSE_PING,                       /* ping  -> request for ping*/
    MSG_PARSE_GETSERVER,                  /* get the right backends for special key */
} msg_parse_result_t;

#define MSG_TYPE_CODEC(ACTION)                                                                      \
    ACTION( UNKNOWN,        unknow )                                                                               \
    ACTION( REQ_MC_GET,     mc_get )                       /* memcache retrieval requests */                    \
    ACTION( REQ_MC_GETS,    mc_gets )                                                                           \
    ACTION( REQ_MC_DELETE,  mc_delete )                    /* memcache delete request */                        \
    ACTION( REQ_MC_CAS,     mc_cas )                       /* memcache cas request and storage request */       \
    ACTION( REQ_MC_SET,     mc_set )                       /* memcache storage request */                       \
    ACTION( REQ_MC_ADD,     mc_add)                                                                            \
    ACTION( REQ_MC_REPLACE, mc_replace)                                                                        \
    ACTION( REQ_MC_APPEND,  mc_append )                                                                         \
    ACTION( REQ_MC_PREPEND, mc_prepend )                                                                        \
    ACTION( REQ_MC_INCR,    mc_incr)                      /* memcache arithmetic request */                    \
    ACTION( REQ_MC_DECR,    mc_decr )                                                                           \
    ACTION( REQ_MC_QUIT,    mc_quit )                      /* memcache quit request */                          \
    ACTION( RSP_MC_NUM,     mc_num )                       /* memcache arithmetic response */                   \
    ACTION( RSP_MC_STORED,  mc_stored )                    /* memcache cas and storage response */              \
    ACTION( RSP_MC_NOT_STORED, mc_not_stored )                                                                     \
    ACTION( RSP_MC_EXISTS,   mc_exists )                                                                         \
    ACTION( RSP_MC_NOT_FOUND, mc_not_found )                                                                      \
    ACTION( RSP_MC_END,    mc_end )                                                                            \
    ACTION( RSP_MC_VALUE,  mc_value )                                                                          \
    ACTION( RSP_MC_DELETED, mc_deleted )                   /* memcache delete response */                       \
    ACTION( RSP_MC_ERROR,   mc_error )                     /* memcache error responses */                       \
    ACTION( RSP_MC_CLIENT_ERROR, mc_client_error )                                                                   \
    ACTION( RSP_MC_SERVER_ERROR, mc_server_error )                                                                   \
    ACTION( REQ_REDIS_DEL,    del )                    /* redis commands - keys */                          \
    ACTION( REQ_REDIS_EXISTS, exists )                                                                      \
    ACTION( REQ_REDIS_EXPIRE, expire )                                                                      \
    ACTION( REQ_REDIS_EXPIREAT, expireat )                                                                    \
    ACTION( REQ_REDIS_PEXPIRE, pexpire )                                                                     \
    ACTION( REQ_REDIS_PEXPIREAT, pexpireat )                                                                   \
    ACTION( REQ_REDIS_PERSIST, persist )                                                                     \
    ACTION( REQ_REDIS_PTTL, pttl )                                                                        \
    ACTION( REQ_REDIS_SORT, sort )                                                                        \
    ACTION( REQ_REDIS_TTL, ttl )                                                                         \
    ACTION( REQ_REDIS_TYPE, type )                                                                        \
    ACTION( REQ_REDIS_APPEND, append )                 /* redis requests - string */                        \
    ACTION( REQ_REDIS_BITCOUNT, bitcount )                                                                    \
    ACTION( REQ_REDIS_DECR, decr )                                                                        \
    ACTION( REQ_REDIS_DECRBY, decrby )                                                                      \
    ACTION( REQ_REDIS_DUMP,dump )                                                                        \
    ACTION( REQ_REDIS_GET,get )                                                                         \
    ACTION( REQ_REDIS_GETBIT, getbit )                                                                      \
    ACTION( REQ_REDIS_GETRANGE, getrange )                                                                    \
    ACTION( REQ_REDIS_GETSET,getset )                                                                      \
    ACTION( REQ_REDIS_INCR,incr )                                                                        \
    ACTION( REQ_REDIS_INCREX, increx )    /* suport incr with ttl         */                                \
    ACTION( REQ_REDIS_INCRBY, incrby )                                                                      \
    ACTION( REQ_REDIS_INCRBYFLOAT,incrbyfloat )                                                                 \
    ACTION( REQ_REDIS_MGET, mget )                                                                        \
    ACTION( REQ_REDIS_MSET, mset )                                                                        \
    ACTION( REQ_REDIS_PSETEX, psetex )                                                                      \
    ACTION( REQ_REDIS_RESTORE, restore )                                                                     \
    ACTION( REQ_REDIS_SET, set )                                                                         \
    ACTION( REQ_REDIS_SETBIT, setbit )                                                                      \
    ACTION( REQ_REDIS_SETEX, setex )                                                                       \
    ACTION( REQ_REDIS_SETNX, setnx )                                                                       \
    ACTION( REQ_REDIS_SETRANGE, setrange )                                                                    \
    ACTION( REQ_REDIS_STRLEN, strlen )                                                                      \
    ACTION( REQ_REDIS_HDEL, hdel )                   /* redis requests - hashes */                        \
    ACTION( REQ_REDIS_HEXISTS, hexists )                                                                     \
    ACTION( REQ_REDIS_HGET, hget )                                                                        \
    ACTION( REQ_REDIS_HGETALL, hgetall )                                                                     \
    ACTION( REQ_REDIS_HMGETALL, hmgetall )                                                                     \
    ACTION( REQ_REDIS_HINCRBY, hincrby )                                                                     \
    ACTION( REQ_REDIS_HINCRBYFLOAT, hincrbyfloat )                                                                \
    ACTION( REQ_REDIS_HKEYS, hkeys )                                                                       \
    ACTION( REQ_REDIS_HLEN, hlen )                                                                        \
    ACTION( REQ_REDIS_HMGET, hmget )                                                                       \
    ACTION( REQ_REDIS_HMSET, hmset )                                                                       \
    ACTION( REQ_REDIS_HSET, hset )                                                                        \
    ACTION( REQ_REDIS_HSETNX, hsetnx )                                                                      \
    ACTION( REQ_REDIS_HSCAN, hscan)                                                                        \
    ACTION( REQ_REDIS_HVALS, hvals )                                                                       \
    ACTION( REQ_REDIS_LINDEX, lindex )                 /* redis requests - lists */                         \
    ACTION( REQ_REDIS_LINSERT, linsert )                                                                     \
    ACTION( REQ_REDIS_LLEN, llen )                                                                        \
    ACTION( REQ_REDIS_LPOP, lpop )                                                                        \
    ACTION( REQ_REDIS_LPUSH, lpush )                                                                       \
    ACTION( REQ_REDIS_LPUSHX, lpushx )                                                                      \
    ACTION( REQ_REDIS_LRANGE, lrange )                                                                      \
    ACTION( REQ_REDIS_LREM, lrem)                                                                        \
    ACTION( REQ_REDIS_LSET, lset )                                                                        \
    ACTION( REQ_REDIS_LTRIM, ltrim )                                                                       \
    ACTION( REQ_REDIS_PFADD,pfadd )                  /* redis requests - hyperloglog */                   \
    ACTION( REQ_REDIS_PFCOUNT,pfcount )                                                                     \
    ACTION( REQ_REDIS_PFMERGE,pfmerge )                                                                     \
    ACTION( REQ_REDIS_RPOP,rpop )                                                                        \
    ACTION( REQ_REDIS_RPOPLPUSH, rpoplpush )                                                                   \
    ACTION( REQ_REDIS_RPUSH, rpush )                                                                       \
    ACTION( REQ_REDIS_RPUSHX, rpushx )                                                                      \
    ACTION( REQ_REDIS_SADD, sadd )                   /* redis requests - sets */                          \
    ACTION( REQ_REDIS_SCARD, scard )                                                                       \
    ACTION( REQ_REDIS_SDIFF, sdiff )                                                                       \
    ACTION( REQ_REDIS_SDIFFSTORE, sdiffstore )                                                                  \
    ACTION( REQ_REDIS_SINTER, sinter )                                                                      \
    ACTION( REQ_REDIS_SINTERSTORE, sinterstore )                                                                 \
    ACTION( REQ_REDIS_SISMEMBER, sismember )                                                                   \
    ACTION( REQ_REDIS_SMEMBERS, smembers )                                                                    \
    ACTION( REQ_REDIS_SMOVE, smove )                                                                       \
    ACTION( REQ_REDIS_SPOP, spop )                                                                        \
    ACTION( REQ_REDIS_SRANDMEMBER, srandmember )                                                                 \
    ACTION( REQ_REDIS_SREM , srem)                                                                        \
    ACTION( REQ_REDIS_SUNION, sunion )                                                                      \
    ACTION( REQ_REDIS_SUNIONSTORE,sunionstore )                                                                 \
    ACTION( REQ_REDIS_SSCAN, sscan)                                                                        \
    ACTION( REQ_REDIS_ZADD, sadd )                   /* redis requests - sorted sets */                   \
    ACTION( REQ_REDIS_ZCARD, scard )                                                                       \
    ACTION( REQ_REDIS_ZCOUNT, scount )                                                                      \
    ACTION( REQ_REDIS_ZINCRBY, zincrby )                                                                     \
    ACTION( REQ_REDIS_ZINTERSTORE, zinterstore )                                                                 \
    ACTION( REQ_REDIS_ZLEXCOUNT,zlexcount )                                                                   \
    ACTION( REQ_REDIS_ZRANGE, zrange )                                                                      \
    ACTION( REQ_REDIS_ZRANGEBYLEX, zrangebylex )                                                                 \
    ACTION( REQ_REDIS_ZRANGEBYSCORE, zrangebyscore )                                                               \
    ACTION( REQ_REDIS_ZRANK, zrank )                                                                       \
    ACTION( REQ_REDIS_ZREM, zrem )                                                                        \
    ACTION( REQ_REDIS_ZREMRANGEBYRANK, zremrangebyrank )                                                             \
    ACTION( REQ_REDIS_ZREMRANGEBYLEX, zremrangebylex )                                                              \
    ACTION( REQ_REDIS_ZREMRANGEBYSCORE, zremrangebyscore )                                                            \
    ACTION( REQ_REDIS_ZREVRANGE, zrevrange )                                                                   \
    ACTION( REQ_REDIS_ZREVRANGEBYSCORE, zrevrangebyscore )                                                            \
    ACTION( REQ_REDIS_ZREVRANK, zrevrank)                                                                    \
    ACTION( REQ_REDIS_ZSCORE, zscore )                                                                      \
    ACTION( REQ_REDIS_ZUNIONSTORE, zunionstore )                                                                 \
    ACTION( REQ_REDIS_ZSCAN, zscan)                                                                        \
    ACTION( REQ_REDIS_EVAL,eval )                   /* redis requests - eval */                          \
    ACTION( REQ_REDIS_EVALSHA, evalsha )                                                                     \
    ACTION( REQ_REDIS_PING, ping )                   /* redis requests - ping/quit */                     \
    ACTION( REQ_REDIS_QUIT, quit)                                                                         \
    ACTION( RSP_REDIS_STATUS, status )                 /* redis response */                                 \
    ACTION( RSP_REDIS_ERROR, error )                                                                       \
    ACTION( RSP_REDIS_INTEGER, integer )                                                                \
    ACTION( RSP_REDIS_BULK, bulk )                                                                        \
    ACTION( RSP_REDIS_MULTIBULK, multibulk )                                                              \
    ACTION( REQ_REDIS_AUTH, auth )                                                                        \
    ACTION( REQ_REDIS_INLINE_AUTH, inline_auth )                                                             \
    ACTION( REQ_REDIS_GETSERVER, getserver )                                                                  \
    ACTION( REQ_REDIS_MGET_SINGLE_REDIS, mget_single_redis )                                                  \
    ACTION( REQ_REDIS_REDIRECT,redirect  )                                                                    \
    ACTION( REQ_REDIS_ECHO, echo )                                                                              \
    ACTION( REQ_NC_STAT, stat )                                                                              \
    ACTION( SENTINEL, sentinel )                                                                              \


#define DEFINE_ACTION(_name, _abc) MSG_##_name,
typedef enum msg_type {
    MSG_TYPE_CODEC(DEFINE_ACTION)
    MSG_MAX_MSG
} msg_type_t;
#undef DEFINE_ACTION




struct keypos {
    uint8_t             *start;           /* key start pos */
    uint8_t             *end;             /* key end pos */
};

struct msg {
    TAILQ_ENTRY(msg)     c_tqe;           /* link in client q */
    TAILQ_ENTRY(msg)     s_tqe;           /* link in server q */
    TAILQ_ENTRY(msg)     m_tqe;           /* link in send q / free q */

    uint64_t             id;              /* message id */
    struct msg           *peer;           /* message peer */
    struct conn          *owner;          /* message owner - client | server */

    struct rbnode        tmo_rbe;         /* entry in rbtree */

    struct mhdr          mhdr;            /* message mbuf header */
    uint32_t             mlen;            /* message length */
    int64_t              start_ts;        /* request start timestamp in usec */

    int                  state;           /* current parser state */
    uint8_t              *pos;            /* parser position marker */
    uint8_t              *token;          /* token marker */

    msg_parse_t          parser;          /* message parser */
    msg_parse_result_t   result;          /* message parsing result */

    msg_fragment_t       fragment;        /* message fragment */
    msg_reply_t          reply;           /* gen message reply (example: ping) */
    msg_coalesce_t       pre_coalesce;    /* message pre-coalesce */
    msg_coalesce_t       post_coalesce;   /* message post-coalesce */

    msg_type_t           type;            /* message type */

    struct array         *keys;           /* array of keypos, for req */

    uint8_t              *key_start;      /* key start */
    uint8_t              *key_end;        /* key end */

    uint8_t              *v_start;        /* value start in mset sub msg */
    uint32_t             v_len;          /* value len   in mset sub msg */

    uint32_t             vlen;            /* value length (memcache) */
    uint8_t              *end;            /* end marker (memcache) */

    uint8_t              *narg_start;     /* narg start (redis) */
    uint8_t              *narg_end;       /* narg end (redis) */
    uint32_t             narg;            /* # arguments (redis) */
    uint32_t             rnarg;           /* running # arg used by parsing fsa (redis) */
    uint32_t             rlen;            /* running length in parsing fsa (redis) */
    uint32_t             integer;         /* integer reply value (redis) */

    struct msg           *frag_owner;     /* owner of fragment message */
    uint32_t             nfrag;           /* # fragment */
    uint32_t             nfrag_done;      /* # fragment done */
    uint64_t             frag_id;         /* id of fragmented message */
    struct msg           **frag_seq;      /* sequence of fragment message, map from keys to fragments*/

    err_t                err;             /* errno on error? */
    unsigned             error:1;         /* error? */
    unsigned             ferror:1;        /* one or more fragments are in error? */
    unsigned             request:1;       /* request? or response? */
    unsigned             quit:1;          /* quit request? */
    unsigned             noreply:1;       /* noreply? */
    unsigned             noforward:1;     /* not need forward (example: ping) */
    unsigned             done:1;          /* done? */
    unsigned             fdone:1;         /* all fragments are done? */

    unsigned             first_fragment:1;/* first fragment? */
    unsigned             last_fragment:1; /* last fragment? */

    unsigned             swallow:1;       /* swallow response? */
    /*
     *  a swallow response is not send to anywhere, just drop it
     */
    unsigned             redis:1;         /* redis? */

    unsigned             transfer_status:2; /* request: the key is in trans?*/
    unsigned             redirect:4;        /* request: redirect? */
    unsigned             redirect_type:1;   /* request: redirect_type 0:key redirect, 1:bucket redirect */
    uint32_t             n_hmgetall_result; /* used for store hmgetall result number */
    int64_t              recv_usec;        /* the time of msg receive from client, usec, 1/10^6 sec*/
};

TAILQ_HEAD(msg_tqh, msg);

struct msg *msg_tmo_min(void);
void msg_tmo_insert(struct msg *msg, struct conn *conn);
void msg_tmo_delete(struct msg *msg);

void msg_init(void);
void msg_deinit(void);
struct string *msg_type_string(msg_type_t type);
struct msg *msg_get(struct conn *conn, bool request, bool redis);
void msg_put(struct msg *msg);
struct msg *msg_get_error(bool redis, err_t err);
void msg_dump(struct msg *msg, int level);
bool msg_empty(struct msg *msg);
rstatus_t msg_recv(struct context *ctx, struct conn *conn);
rstatus_t msg_send(struct context *ctx, struct conn *conn);
uint64_t msg_gen_frag_id(void);
uint32_t msg_backend_idx(struct msg *msg, uint8_t *key, uint32_t keylen);
struct mbuf *msg_ensure_mbuf(struct msg *msg, size_t len);
rstatus_t msg_append(struct msg *msg, uint8_t *pos, size_t n);
rstatus_t msg_prepend(struct msg *msg, uint8_t *pos, size_t n);
rstatus_t msg_prepend_format(struct msg *msg, const char *fmt, ...);

struct msg *req_get(struct conn *conn);
void req_put(struct msg *msg);
bool req_done(struct conn *conn, struct msg *msg);
bool req_error(struct conn *conn, struct msg *msg);
void req_server_enqueue_imsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_server_dequeue_imsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_client_enqueue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_server_enqueue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_client_dequeue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_server_dequeue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
struct msg *req_recv_next(struct context *ctx, struct conn *conn, bool alloc);
void req_recv_done(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *nmsg);
struct msg *req_send_next(struct context *ctx, struct conn *conn);
void req_send_done(struct context *ctx, struct conn *conn, struct msg *msg);

struct msg *rsp_get(struct conn *conn);
void rsp_put(struct msg *msg);
struct msg *rsp_recv_next(struct context *ctx, struct conn *conn, bool alloc);
void rsp_recv_done(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *nmsg);
struct msg *rsp_send_next(struct context *ctx, struct conn *conn);
void rsp_send_done(struct context *ctx, struct conn *conn, struct msg *msg);



#endif
