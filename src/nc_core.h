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

#ifndef _NC_CORE_H_
#define _NC_CORE_H_

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef HAVE_DEBUG_LOG
# define NC_DEBUG_LOG 1
#endif

#ifdef HAVE_ASSERT_PANIC
# define NC_ASSERT_PANIC 1
#endif

#ifdef HAVE_ASSERT_LOG
# define NC_ASSERT_LOG 1
#endif

#ifdef HAVE_STATS
# define NC_STATS 1
#else
# define NC_STATS 0
#endif

#ifdef HAVE_EPOLL
# define NC_HAVE_EPOLL 1
#elif HAVE_KQUEUE
# define NC_HAVE_KQUEUE 1
#elif HAVE_EVENT_PORTS
# define NC_HAVE_EVENT_PORTS 1
#else
# error missing scalable I/O event notification mechanism
#endif

#ifdef HAVE_LITTLE_ENDIAN
# define NC_LITTLE_ENDIAN 1
#endif

#ifdef HAVE_BACKTRACE
# define NC_HAVE_BACKTRACE 1
#endif

#define NC_OK        0
#define NC_ERROR    -1
#define NC_EAGAIN   -2
#define NC_ENOMEM   -3
#define NC_DEF_CONF -4

/* reserved fds for std streams, log, stats fd, epoll etc. */
#define RESERVED_FDS 32

#define NC_MAX_NSERVER 10240 /*FOR SERVER POOL*/

#define NC_REQ_STAT_RANGER_MAX 16

typedef int rstatus_t; /* return type */
typedef int err_t;     /* error type */

struct array;
struct string;
struct context;
struct conn;
struct conn_tqh;
struct msg;
struct msg_tqh;
struct server;
struct server_pool;
struct mbuf;
struct mhdr;
struct conf;
struct stats;
struct instance;
struct event_base;

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>

#include <nc_array.h>
#include <nc_string.h>
#include <nc_queue.h>
#include <nc_rbtree.h>
#include <nc_log.h>
#include <nc_util.h>
#include <event/nc_event.h>
#include <nc_stats.h>
#include <nc_mbuf.h>
#include <nc_message.h>
#include <nc_connection.h>
#include <nc_server.h>
#include <sds.h>


struct reqCommand {
    char *name;
    long long microseconds, calls;
    int32_t kus_start, kus_end;
};


//struct reqCommand reqStatTable[MSG_REQ_MAX_VALUE] = {};

struct context {
    uint32_t           id;          /* unique context id */
    struct conf        *cf;         /* configuration */
    struct stats       *stats;      /* stats */

    struct array       pool;        /* server_pool[] */
    struct event_base  *evb;        /* event base */
    int                max_timeout; /* max timeout in msec */
    int                timeout;     /* timeout in msec */

    uint32_t           max_nfd;     /* max # files */
    uint32_t           max_ncconn;  /* max # client connections */
    uint32_t           max_nsconn;  /* max # server connections */
    uint32_t           slowms;
    struct reqCommand  *req_stats;   /* item num: enum last item, REQ_MAX_VALUE */
    struct reqCommand  range_stats[NC_REQ_STAT_RANGER_MAX+1] ; /* ranger status [0us, 1000us 2000us 4000us 8000us 16000us 32000us 64000us 128ms 256ms 512ms 1024ms 2048m 4096ms 8s 16s 32s] */
};


struct instance {
    struct context  *ctx;                        /* active context */
    int             log_level;                   /* log level */
    char            *log_filename;               /* log filename */
    char            *conf_filename;              /* configuration filename */
    uint16_t        stats_port;                  /* stats monitoring port */
    int             stats_interval;              /* stats aggregation interval */
    char            *stats_addr;                 /* stats monitoring addr */
    char            hostname[NC_MAXHOSTNAMELEN]; /* hostname */
    size_t          mbuf_chunk_size;             /* mbuf chunk size */
    pid_t           pid;                         /* process id */
    char            *pid_filename;               /* pid filename */
    unsigned        pidfile:1;                   /* pid file created? */
};

struct context *core_start(struct instance *nci);
void core_stop(struct context *ctx);
rstatus_t core_core(void *arg, uint32_t events);
rstatus_t core_loop(struct context *ctx);
void core_close(struct context *ctx, struct conn *conn);


#endif
