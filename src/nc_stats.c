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
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <nc_core.h>
#include <nc_server.h>

struct stats_desc {
    char *name; /* stats name */
    char *desc; /* stats description */
};

#define DEFINE_ACTION(_name, _type, _desc) { .type = _type, .name = string(#_name) },
static struct stats_metric stats_pool_codec[] = {
    STATS_POOL_CODEC( DEFINE_ACTION )
};

static struct stats_metric stats_server_codec[] = {
    STATS_SERVER_CODEC( DEFINE_ACTION )
};
#undef DEFINE_ACTION

#define DEFINE_ACTION(_name, _type, _desc) { .name = #_name, .desc = _desc },
static struct stats_desc stats_pool_desc[] = {
    STATS_POOL_CODEC( DEFINE_ACTION )
};

static struct stats_desc stats_server_desc[] = {
    STATS_SERVER_CODEC( DEFINE_ACTION )
};
#undef DEFINE_ACTION

void
stats_describe(void)
{
    uint32_t i;

    log_stderr("pool stats:");
    for (i = 0; i < NELEMS(stats_pool_desc); i++) {
        log_stderr("  %-20s\"%s\"", stats_pool_desc[i].name,
                   stats_pool_desc[i].desc);
    }

    log_stderr("");

    log_stderr("server stats:");
    for (i = 0; i < NELEMS(stats_server_desc); i++) {
        log_stderr("  %-20s\"%s\"", stats_server_desc[i].name,
                   stats_server_desc[i].desc);
    }
}

static void
stats_metric_init(struct stats_metric *stm)
{
    switch (stm->type) {
    case STATS_COUNTER:
        stm->value.counter = 0LL;
        break;

    case STATS_GAUGE:
        stm->value.counter = 0LL;
        break;

    case STATS_TIMESTAMP:
        stm->value.timestamp = 0LL;
        break;

    default:
        NOT_REACHED();
    }
}

static void
stats_metric_reset(struct array *stats_metric)
{
    uint32_t i, nmetric;

    nmetric = array_n(stats_metric);
    ASSERT(nmetric == STATS_POOL_NFIELD || nmetric == STATS_SERVER_NFIELD);

    for (i = 0; i < nmetric; i++) {
        struct stats_metric *stm = array_get(stats_metric, i);

        stats_metric_init(stm);
    }
}

static rstatus_t
stats_pool_metric_init(struct array *stats_metric)
{
    rstatus_t status;
    uint32_t i, nfield = STATS_POOL_NFIELD;

    status = array_init(stats_metric, nfield, sizeof(struct stats_metric));
    if (status != NC_OK) {
        return status;
    }

    for (i = 0; i < nfield; i++) {
        struct stats_metric *stm = array_push(stats_metric);

        /* initialize from pool codec first */
        *stm = stats_pool_codec[i];

        /* initialize individual metric */
        stats_metric_init(stm);
    }

    return NC_OK;
}

static rstatus_t
stats_server_metric_init(struct stats_server *sts)
{
    rstatus_t status;
    uint32_t i, nfield = STATS_SERVER_NFIELD;

    status = array_init(&sts->metric, nfield, sizeof(struct stats_metric));
    if (status != NC_OK) {
        return status;
    }

    for (i = 0; i < nfield; i++) {
        struct stats_metric *stm = array_push(&sts->metric);

        /* initialize from server codec first */
        *stm = stats_server_codec[i];

        /* initialize individual metric */
        stats_metric_init(stm);
    }

    return NC_OK;
}

static void
stats_metric_deinit(struct array *metric)
{
    uint32_t i, nmetric;

    nmetric = array_n(metric);
    for (i = 0; i < nmetric; i++) {
        array_pop(metric);
    }
    array_deinit(metric);
}

static rstatus_t
stats_server_init(struct stats_server *sts, struct server *s)
{
    rstatus_t status;

    sts->name = s->name;
    array_null(&sts->metric);

    status = stats_server_metric_init(sts);
    if (status != NC_OK) {
        return status;
    }

    log_debug(LOG_VVVERB, "init stats server '%.*s' with %"PRIu32" metric",
              sts->name.len, sts->name.data, array_n(&sts->metric));

    return NC_OK;

}

static rstatus_t
stats_server_map(struct array *stats_server, struct array *server)
{
    rstatus_t status;
    uint32_t i, nserver;

    nserver = array_n(server);
    ASSERT(nserver != 0);

    status = array_init(stats_server, NC_MAX_NSERVER, sizeof(struct stats_server));
    if (status != NC_OK) {
        return status;
    }
    log_debug(LOG_VVVERB, "pre alloc %d stats servers, size:%d bytes", NC_MAX_NSERVER, NC_MAX_NSERVER * sizeof(struct stats_server));

    for (i = 0; i < nserver; i++) {
        struct server *s = array_get(server, i);
        struct stats_server *sts = array_push(stats_server);

        status = stats_server_init(sts, s);
        if (status != NC_OK) {
            return status;
        }
    }

    log_debug(LOG_VVVERB, "map %"PRIu32" stats servers", nserver);

    return NC_OK;
}


rstatus_t stats_pool_change_server_name(struct server_pool *pool, uint32_t idx, char* name) {
	rstatus_t status;
	struct stats_pool *stp;

	stp = array_get(&pool->ctx->stats->current, pool->idx);
	status = stats_server_change_name(&stp->server, idx, name);
	if (NC_OK != status) {
		return status;
	}

	stp = array_get(&pool->ctx->stats->shadow, pool->idx);
	status = stats_server_change_name(&stp->server, idx, name);
	if (NC_OK != status) {
		//FIXME: deinit current
		return status;
	}

	stp = array_get(&pool->ctx->stats->sum, pool->idx);
	status = stats_server_change_name(&stp->server, idx, name);
	if (NC_OK != status) {
		//FIXME: deinit current\shadow
		return status;
	}

	stats_destroy_buf(pool->ctx->stats);
	stats_create_buf(pool->ctx->stats);


	return NC_OK;
}


rstatus_t stats_server_change_name(struct array *stats_server,  uint32_t idx, char *name) {
	rstatus_t status;
	struct stats_pool *stp;
	struct stats_server *s = array_get(stats_server, idx);
	s->name.data = (uint8_t*)name;
	s->name.len = (uint32_t)nc_strlen(name);
	log_error ("stats_server_change_name %d %s",  idx, name);
	return NC_OK;
}

rstatus_t stats_pool_add_server(struct server_pool *pool, uint32_t newsvr_idx) {
	rstatus_t status;
	struct stats_pool *stp;

	stp = array_get(&pool->ctx->stats->current, pool->idx);
	status = stats_server_add_one(&stp->server, &pool->server, newsvr_idx);
	if (NC_OK != status) {
		return status;
	}

	stp = array_get(&pool->ctx->stats->shadow, pool->idx);
	status = stats_server_add_one(&stp->server, &pool->server, newsvr_idx);
	if (NC_OK != status) {
		//FIXME: deinit current
		return status;
	}

	stp = array_get(&pool->ctx->stats->sum, pool->idx);
	status = stats_server_add_one(&stp->server, &pool->server, newsvr_idx);
	if (NC_OK != status) {
		//FIXME: deinit current\shadow
		return status;
	}

	stats_destroy_buf(pool->ctx->stats);
	stats_create_buf(pool->ctx->stats);


	return NC_OK;
}
/*
 * add a new server in alloced array. idx must < NC_MAX_SERVER to avoid realloc
 *  status = stats_pool_map(&st->current, server_pool);
 * */
rstatus_t stats_server_add_one(struct array *stats_server, struct array *server, uint32_t newsvr_idx) {
	rstatus_t status;
	ASSERT(stats_server != NULL); ASSERT(server != NULL);

	struct server *s = array_get(server, newsvr_idx);
	if (s->idx != newsvr_idx) {
		return NC_ERROR;
	}

	if (newsvr_idx >= stats_server->nalloc) {
		return NC_ERROR;
	}

	struct stats_server *sts = array_push(stats_server);

	status = stats_server_init(sts, s);
	if (status != NC_OK) {
		return status;
	}

//   log_debug(LOG_VVVERB, "%s add map %"PRIu32" stats servers", newsvr_idx);

	return NC_OK;
}

static void
stats_server_unmap(struct array *stats_server)
{
    uint32_t i, nserver;

    nserver = array_n(stats_server);

    for (i = 0; i < nserver; i++) {
        struct stats_server *sts = array_pop(stats_server);
        stats_metric_deinit(&sts->metric);
    }
    array_deinit(stats_server);

    log_debug(LOG_VVVERB, "unmap %"PRIu32" stats servers", nserver);
}

static rstatus_t
stats_pool_init(struct stats_pool *stp, struct server_pool *sp)
{
    rstatus_t status;

    stp->name = sp->name;
    array_null(&stp->metric);
    array_null(&stp->server);

    status = stats_pool_metric_init(&stp->metric);
    if (status != NC_OK) {
        return status;
    }

    status = stats_server_map(&stp->server, &sp->server);
    if (status != NC_OK) {
        stats_metric_deinit(&stp->metric);
        return status;
    }

    log_debug(LOG_VVVERB, "init stats pool '%.*s' with %"PRIu32" metric and "
              "%"PRIu32" server", stp->name.len, stp->name.data,
              array_n(&stp->metric), array_n(&stp->metric));

    return NC_OK;
}

static void
stats_pool_reset(struct array *stats_pool)
{
    uint32_t i, npool;

    npool = array_n(stats_pool);

    for (i = 0; i < npool; i++) {
        struct stats_pool *stp = array_get(stats_pool, i);
        uint32_t j, nserver;

        stats_metric_reset(&stp->metric);

        nserver = array_n(&stp->server);
        for (j = 0; j < nserver; j++) {
            struct stats_server *sts = array_get(&stp->server, j);
            stats_metric_reset(&sts->metric);
        }
    }
}

static rstatus_t
stats_pool_map(struct array *stats_pool, struct array *server_pool)
{
    rstatus_t status;
    uint32_t i, npool;

    npool = array_n(server_pool);
    ASSERT(npool != 0);

    status = array_init(stats_pool, npool, sizeof(struct stats_pool));
    if (status != NC_OK) {
        return status;
    }

    for (i = 0; i < npool; i++) {
        struct server_pool *sp = array_get(server_pool, i);
        struct stats_pool *stp = array_push(stats_pool);

        status = stats_pool_init(stp, sp);
        if (status != NC_OK) {
            return status;
        }
    }

    log_debug(LOG_VVVERB, "map %"PRIu32" stats pools", npool);

    return NC_OK;
}

static void
stats_pool_unmap(struct array *stats_pool)
{
    uint32_t i, npool;

    npool = array_n(stats_pool);

    for (i = 0; i < npool; i++) {
        struct stats_pool *stp = array_pop(stats_pool);
        stats_metric_deinit(&stp->metric);
        stats_server_unmap(&stp->server);
    }
    array_deinit(stats_pool);

    log_debug(LOG_VVVERB, "unmap %"PRIu32" stats pool", npool);
}

rstatus_t
stats_create_buf(struct stats *st)
{
    uint32_t int64_max_digits = 20; /* INT64_MAX = 9223372036854775807 */
    uint32_t key_value_extra = 8;   /* "key": "value", */
    uint32_t pool_extra = 8;        /* '"pool_name": { ' + ' }' */
    uint32_t server_extra = 8;      /* '"server_name": { ' + ' }' */
    size_t size = 0;
    uint32_t i;

    ASSERT(st->buf.data == NULL && st->buf.size == 0);

    /* header */
    size += 1;

    size += st->service_str.len;
    size += st->service.len;
    size += key_value_extra;

    size += st->source_str.len;
    size += st->source.len;
    size += key_value_extra;

    size += st->version_str.len;
    size += st->version.len;
    size += key_value_extra;

    size += st->uptime_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    size += st->timestamp_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    size += st->ntotal_conn_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    size += st->ncurr_conn_str.len;
    size += int64_max_digits;
    size += key_value_extra;

    /* server pools */
    for (i = 0; i < array_n(&st->sum); i++) {
        struct stats_pool *stp = array_get(&st->sum, i);
        uint32_t j;

        size += stp->name.len;
        size += pool_extra;

        for (j = 0; j < array_n(&stp->metric); j++) {
            struct stats_metric *stm = array_get(&stp->metric, j);

            size += stm->name.len;
            size += int64_max_digits;
            size += key_value_extra;
        }

        /* servers per pool */
        for (j = 0; j < array_n(&stp->server); j++) {
            struct stats_server *sts = array_get(&stp->server, j);
            uint32_t k;

            size += sts->name.len;
            size += server_extra;

            for (k = 0; k < array_n(&sts->metric); k++) {
                struct stats_metric *stm = array_get(&sts->metric, k);

                size += stm->name.len;
                size += int64_max_digits;
                size += key_value_extra;
            }
        }
    }

    /* footer */
    size += 2;

    size = NC_ALIGN(size, NC_ALIGNMENT);

    st->buf.data = nc_alloc(size);
    if (st->buf.data == NULL) {
        log_error("create stats buffer of size %zu failed: %s", size,
                   strerror(errno));
        return NC_ENOMEM;
    }
    st->buf.size = size;

    log_debug(LOG_DEBUG, "stats buffer size %zu", size);

    return NC_OK;
}

void
stats_destroy_buf(struct stats *st)
{
    if (st->buf.size != 0) {
        ASSERT(st->buf.data != NULL);
        nc_free(st->buf.data);
        st->buf.size = 0;
    }
}

static rstatus_t
stats_add_string(struct stats *st, struct string *key, struct string *val)
{
    struct stats_buffer *buf;
    uint8_t *pos;
    size_t room;
    int n;

    buf = &st->buf;
    pos = buf->data + buf->len;
    room = buf->size - buf->len - 1;

    n = nc_snprintf(pos, room, "\"%.*s\":\"%.*s\", ", key->len, key->data,
                    val->len, val->data);
    if (n < 0 || n >= (int)room) {
        return NC_ERROR;
    }

    buf->len += (size_t)n;

    return NC_OK;
}

static rstatus_t
stats_add_num(struct stats *st, struct string *key, int64_t val)
{
    struct stats_buffer *buf;
    uint8_t *pos;
    size_t room;
    int n;

    buf = &st->buf;
    pos = buf->data + buf->len;
    room = buf->size - buf->len - 1;

    n = nc_snprintf(pos, room, "\"%.*s\":%"PRId64", ", key->len, key->data,
                    val);
    if (n < 0 || n >= (int)room) {
    	log_error ("add error %d %s %d ", n, pos, room);
        return NC_ERROR;
    }

    buf->len += (size_t)n;

    return NC_OK;
}

static rstatus_t
stats_add_header(struct stats *st)
{
    rstatus_t status;
    struct stats_buffer *buf;
    int64_t cur_ts, uptime;

    buf = &st->buf;
    buf->data[0] = '{';
    buf->len = 1;

    cur_ts = (int64_t)time(NULL);
    uptime = cur_ts - st->start_ts;

    status = stats_add_string(st, &st->service_str, &st->service);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_string(st, &st->source_str, &st->source);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_string(st, &st->version_str, &st->version);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->uptime_str, uptime);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->timestamp_str, cur_ts);
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->ntotal_conn_str, conn_ntotal_conn());
    if (status != NC_OK) {
        return status;
    }

    status = stats_add_num(st, &st->ncurr_conn_str, conn_ncurr_conn());
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

static rstatus_t
stats_add_footer(struct stats *st)
{
    struct stats_buffer *buf;
    uint8_t *pos;

    buf = &st->buf;

    if (buf->len == buf->size) {
        return NC_ERROR;
    }

    /* overwrite the last byte and add a new byte */
    pos = buf->data + buf->len - 1;
    pos[0] = '}';
    pos[1] = '\n';
    buf->len += 1;

    return NC_OK;
}

static rstatus_t
stats_begin_nesting(struct stats *st, struct string *key)
{
    struct stats_buffer *buf;
    uint8_t *pos;
    size_t room;
    int n;

    buf = &st->buf;
    pos = buf->data + buf->len;
    room = buf->size - buf->len - 1;

    n = nc_snprintf(pos, room, "\"%.*s\": {", key->len, key->data);
    if (n < 0 || n >= (int)room) {
        return NC_ERROR;
    }

    buf->len += (size_t)n;

    return NC_OK;
}

static rstatus_t
stats_end_nesting(struct stats *st)
{
    struct stats_buffer *buf;
    uint8_t *pos;

    buf = &st->buf;
    pos = buf->data + buf->len;

    pos -= 2; /* go back by 2 bytes */

    switch (pos[0]) {
    case ',':
        /* overwrite last two bytes; len remains unchanged */
        ASSERT(pos[1] == ' ');
        pos[0] = '}';
        pos[1] = ',';
        break;

    case '}':
        if (buf->len == buf->size) {
            return NC_ERROR;
        }
        /* overwrite the last byte and add a new byte */
        ASSERT(pos[1] == ',');
        pos[1] = '}';
        pos[2] = ',';
        buf->len += 1;
        break;

    default:
        NOT_REACHED();
    }

    return NC_OK;
}

static rstatus_t
stats_copy_metric(struct stats *st, struct array *metric)
{
    rstatus_t status;
    uint32_t i;

    for (i = 0; i < array_n(metric); i++) {
        struct stats_metric *stm = array_get(metric, i);

        status = stats_add_num(st, &stm->name, stm->value.counter);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}

static void
stats_aggregate_metric(struct array *dst, struct array *src)
{
    uint32_t i;

    for (i = 0; i < array_n(src); i++) {
        struct stats_metric *stm1, *stm2;

        stm1 = array_get(src, i);
        stm2 = array_get(dst, i);

        ASSERT(stm1->type == stm2->type);

        switch (stm1->type) {
        case STATS_COUNTER:
            stm2->value.counter += stm1->value.counter;
            break;

        case STATS_GAUGE:
            stm2->value.counter += stm1->value.counter;
            break;

        case STATS_TIMESTAMP:
            if (stm1->value.timestamp) {
                stm2->value.timestamp = stm1->value.timestamp;
            }
            break;

        default:
            NOT_REACHED();
        }
    }
}

static void
stats_aggregate(struct stats *st)
{
    uint32_t i;

    if (st->aggregate == 0) {
        log_debug(LOG_PVERB, "skip aggregate of shadow %p to sum %p as "
                  "generator is slow", st->shadow.elem, st->sum.elem);
        return;
    }

    log_debug(LOG_PVERB, "aggregate stats shadow %p to sum %p", st->shadow.elem,
              st->sum.elem);

    for (i = 0; i < array_n(&st->shadow); i++) {
        struct stats_pool *stp1, *stp2;
        uint32_t j;

        stp1 = array_get(&st->shadow, i);
        stp2 = array_get(&st->sum, i);
        stats_aggregate_metric(&stp2->metric, &stp1->metric);

        for (j = 0; j < array_n(&stp1->server); j++) {
            struct stats_server *sts1, *sts2;

            sts1 = array_get(&stp1->server, j);
            sts2 = array_get(&stp2->server, j);
            stats_aggregate_metric(&sts2->metric, &sts1->metric);
        }
    }

    st->aggregate = 0;
}

static rstatus_t
stats_make_rsp(struct stats *st)
{
    rstatus_t status;
    uint32_t i;

    status = stats_add_header(st);
    if (status != NC_OK) {
        return status;
    }

    for (i = 0; i < array_n(&st->sum); i++) {
        struct stats_pool *stp = array_get(&st->sum, i);
        uint32_t j;
        uint32_t  n;

        status = stats_begin_nesting(st, &stp->name);
        if (status != NC_OK) {
            return status;
        }

        /* copy pool metric from sum(c) to buffer */
        status = stats_copy_metric(st, &stp->metric);
        if (status != NC_OK) {
            return status;
        }

        for (j = 0; j < array_n(&stp->server); j++) {
            struct stats_server *sts = array_get(&stp->server, j);

            status = stats_begin_nesting(st, &sts->name);
            if (status != NC_OK) {
                return status;
            }

            /* copy server metric from sum(c) to buffer */

            status = stats_copy_metric(st, &sts->metric);
            if (status != NC_OK) {
            	//log_error ("stats_copy_metric failed i=%d j=%d addr:%s", i,j, st->addr.data);
                return status;
            }

            status = stats_end_nesting(st);
            if (status != NC_OK) {
                return status;
            }
        }

        status = stats_end_nesting(st);
        if (status != NC_OK) {
            return status;
        }
    }

    status = stats_add_footer(st);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}




static rstatus_t stats_send_rsp(struct stats *st) {
	rstatus_t status;
	ssize_t n;
	int sd, rt;
	char recv_command[MAX_COMMAND_LENGTH * MAX_COMMAND_FIELD];
	char *cmd_p[MAX_COMMAND_FIELD];
	char *p, *key_point;
	int n_field;
	char *result = NULL;
	char *output = NULL;

	status = stats_make_rsp(st);

	if (status != NC_OK) {
		log_error("stats_make_rsp failed");
		//return status;
	}
	memset(recv_command, 0, sizeof(recv_command));
	sd = accept(st->sd, NULL, NULL);
	if (sd < 0) {
		log_error("accept on m %d failed: %s", st->sd, strerror(errno));
		return NC_ERROR;
	}


	//memset(recv_command, 0, sizeof(recv_command));
	n = recv(sd, recv_command, 80, 0);
	if (n >= 2 && recv_command[n - 2] == CR && recv_command[n - 1] == LF) {
		recv_command[n - 2] = recv_command[n - 1] = 0;
	} else if (n >= 1 && recv_command[n - 1] == LF) {
		recv_command[n - 1] = 0;
	}




	/* get rid of head,tail space */
	nc_trim(recv_command);
	log_debug(LOG_VERB,"receive length:%d, command:'%s' %d %d %d",n,recv_command,strlen(recv_command),recv_command[n-2],recv_command[n-1]);

	// null command
	if (strlen(recv_command) < 1) {
		char str_e[] = "ERR:empty command";
		n = nc_sendn(sd, str_e, strlen(str_e));
		goto end;
	}

	// cut the command into many fields
	p = recv_command;
	n_field = 0;
	while (p) {
		while ((key_point = strsep(&p, " \t"))) {
			if (*key_point == 0)
				continue;
			else
				break;
		}

		cmd_p[n_field++] = key_point;
	}

	// too many fields
	if (n_field >= MAX_COMMAND_FIELD) {
		char str_e[] = "ERR:bad command: too many field in command\n";
		n = nc_sendn(sd, str_e, strlen(str_e));
		goto end;
	}



	/* get the stats info of twemproxy */
	if (!strcmp(cmd_p[0], "stats")) {
		log_debug(LOG_VERB, "send stats on sd %d %d bytes", sd, st->buf.len);
		n = nc_sendn(sd, st->buf.data, st->buf.len);
	    if (n < 0) {
	        log_error("send stats on sd %d failed: %s", sd, strerror(errno));
	        close(sd);
	        return NC_ERROR;
	    }
		goto end;
	}

	result = nc_alloc(STATS_RESULT_BUFLEN + 1);
	output = nc_alloc(STATS_RESULT_BUFLEN + 1);

	if (!result || !output) {
		char str_e[] = "ERR:malloc failed\n";
		n = nc_sendn(sd, str_e, strlen(str_e));
		goto end;
	}

	memset(result, '0', STATS_RESULT_BUFLEN + 1);
	memset(output, '0', STATS_RESULT_BUFLEN + 1);

	/*
	 * get spname servers
	 * 	return the server list
	 * get spname listen
	 * 	return the value of listen
	 * */
	if (!strcmp(cmd_p[0], "get") && n_field == 3) { /* get config */
		if (!strcmp(cmd_p[2], "password") || !strcmp(cmd_p[2], "redis_password") ) {
			rt = NC_ERROR;
			snprintf(result, STATS_RESULT_BUFLEN, "ERR: get command, bad segname '%s'",  cmd_p[2] );
		} else if (!strcmp(cmd_p[2], "servers")) {
			rt = sp_get_by_item(cmd_p[1], "server", result, st->p_sp);
		} else if (!strcmp(cmd_p[2], "transinfo")) {
			rt = sp_get_by_item(cmd_p[1], "transinfo", result, st->p_sp);
		} else {
			rt = conf_get_by_item((uint8_t *) cmd_p[1], (uint8_t *) cmd_p[2], result, st->p_cf);
		}
		if (rt != NC_OK) {
			log_error("err ret:%d . msg: %s", rt, result);
		}
		n = nc_sendn(sd, result, strlen(result));

	}
	/*
	 * add spname ip:port app segS-segE status
	 *
	 */

	else if (!strcmp(cmd_p[0], "add") ) {
		if (n_field != 5) {
			snprintf(output, STATS_RESULT_BUFLEN, "ERR: add command, bad argument\n");
		} else {
			/*                       echo " 0 add  1 alpha 127.0.0.1:30002 pvz1 21-30  2" |nc  127.0.0.1 22222 */
			/*  (void *sp, char *sp_name, char *inst, char* app, char *segs, char *status, char *result) */
			rt = nc_stats_addCommand(st->p_sp, cmd_p[1], cmd_p[2], cmd_p[3], cmd_p[4], "2", result);
			if (NC_OK == rt) {
				snprintf(output, STATS_RESULT_BUFLEN, "OK\n");
			} else {
				snprintf(output, STATS_RESULT_BUFLEN, "ERR: %s\n", result);
			}
		}

		n = nc_sendn(sd, output, strlen(output));

	}
	/*
	 * adddone, set status 2 to 1
	 * */
	else if (!strcmp(cmd_p[0], "adddone")) {
		if (n_field != 5) {
			snprintf(output, STATS_RESULT_BUFLEN, "ERR: adddone command, bad argument\n");
		} else {
			rt = nc_stats_addDoneCommand(st->p_sp, cmd_p[1], cmd_p[2], cmd_p[3], cmd_p[4], "2", result);
			if (NC_OK == rt) {
				snprintf(output, STATS_RESULT_BUFLEN, "OK\n");
			} else {
				snprintf(output, STATS_RESULT_BUFLEN, "ERR: %s\n", result);
			}
		}

		n = nc_sendn(sd, output, strlen(output));
	}

	/*
	 * change spname ipport new_ipport
	 */

	else if (!strcmp(cmd_p[0], "change") && n_field == 4) { /* change status */
		log_error ("change %s %s %s", cmd_p[1], cmd_p[2], cmd_p[3]);
		rt = nc_server_change_instance(st->p_sp, cmd_p[1], cmd_p[2], cmd_p[3], result);

		if (rt != NC_OK) {
			log_error("nc_server_change_instance failed:%d %s\n", rt, result);
		}

		n = nc_sendn(sd, result, strlen(result));

	} else if (!strcmp(cmd_p[0], "delete")) { /* delete server */

	} else if (!strcmp(cmd_p[0], "getkey") && n_field == 3) { /* get hashkey  backend's info */
		rt = server_pool_getkey_by_keyid(st->p_sp, cmd_p[1], cmd_p[2], result);
		log_error("receive stats command: getkey %s %s", cmd_p[1], cmd_p[2]);
		n = nc_sendn(sd, result, strlen(result));
	} else {
		char str_e[] = "unkown command.\n";
		log_debug(LOG_VERB,"%s",str_e);
		n = nc_sendn(sd, str_e, strlen(str_e));
	}


end:

	if (result) nc_free(result);
	if (output) nc_free(output);

	if (n < 0) {
		log_error("send stats on sd %d failed: %s", sd, strerror(errno));
		close(sd);
		return NC_ERROR;
	} else {
		log_error("send %d bytes stats on sd %d",n, sd);
	}

	close(sd);
	return NC_OK;
}

static void
stats_loop_callback(void *arg1, void *arg2)
{
    struct stats *st = arg1;
    int n = *((int *)arg2);

    /* aggregate stats from shadow (b) -> sum (c) */
    stats_aggregate(st);

    if (n == 0) {
        return;
    }

    /* send aggregate stats sum (c) to collector */
    stats_send_rsp(st);
}

static void *
stats_loop(void *arg)
{
    event_loop_stats(stats_loop_callback, arg);
    return NULL;
}

static rstatus_t
stats_listen(struct stats *st)
{
    rstatus_t status;
    struct sockinfo si;

    status = nc_resolve(&st->addr, st->port, &si);
    if (status < 0) {
        return status;
    }

    st->sd = socket(si.family, SOCK_STREAM, 0);
    if (st->sd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return NC_ERROR;
    }

    status = nc_set_reuseaddr(st->sd);
    if (status < 0) {
        log_error("set reuseaddr on m %d failed: %s", st->sd, strerror(errno));
        return NC_ERROR;
    }

    status = bind(st->sd, (struct sockaddr *)&si.addr, si.addrlen);
    if (status < 0) {
        log_error("bind on m %d to addr '%.*s:%u' failed: %s", st->sd,
                  st->addr.len, st->addr.data, st->port, strerror(errno));
        return NC_ERROR;
    }

    status = listen(st->sd, SOMAXCONN);
    if (status < 0) {
        log_error("listen on m %d failed: %s", st->sd, strerror(errno));
        return NC_ERROR;
    }

    log_debug(LOG_NOTICE, "m %d listening on '%.*s:%u'", st->sd,
              st->addr.len, st->addr.data, st->port);

    return NC_OK;
}

static rstatus_t
stats_start_aggregator(struct stats *st)
{
    rstatus_t status;

    if (!stats_enabled) {
        return NC_OK;
    }

    status = stats_listen(st);
    if (status != NC_OK) {
        return status;
    }

    status = pthread_create(&st->tid, NULL, stats_loop, st);
    if (status < 0) {
        log_error("stats aggregator create failed: %s", strerror(status));
        return NC_ERROR;
    }

    return NC_OK;
}

static void
stats_stop_aggregator(struct stats *st)
{
    if (!stats_enabled) {
        return;
    }

    close(st->sd);
}

struct stats *
stats_create(uint16_t stats_port, char *stats_ip, int stats_interval,
             char *source, struct array *server_pool)
{
    rstatus_t status;
    struct stats *st;

    st = nc_alloc(sizeof(*st));
    if (st == NULL) {
        return NULL;
    }

    st->port = stats_port;
    st->interval = stats_interval;
    string_set_raw(&st->addr, stats_ip);

    st->start_ts = (int64_t)time(NULL);

    st->buf.len = 0;
    st->buf.data = NULL;
    st->buf.size = 0;

    array_null(&st->current);
    array_null(&st->shadow);
    array_null(&st->sum);

    st->tid = (pthread_t) -1;
    st->sd = -1;

    string_set_text(&st->service_str, "service");
    string_set_text(&st->service, "nutcracker");

    string_set_text(&st->source_str, "source");
    string_set_raw(&st->source, source);

    string_set_text(&st->version_str, "version");
    string_set_text(&st->version, NC_VERSION_STRING);

    string_set_text(&st->uptime_str, "uptime");
    string_set_text(&st->timestamp_str, "timestamp");

    string_set_text(&st->ntotal_conn_str, "total_connections");
    string_set_text(&st->ncurr_conn_str, "curr_connections");

    st->updated = 0;
    st->aggregate = 0;

    /* map server pool to current (a), shadow (b) and sum (c) */

    status = stats_pool_map(&st->current, server_pool);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_pool_map(&st->shadow, server_pool);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_pool_map(&st->sum, server_pool);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_create_buf(st);
    if (status != NC_OK) {
        goto error;
    }

    status = stats_start_aggregator(st);
    if (status != NC_OK) {
        goto error;
    }

    return st;

error:
    stats_destroy(st);
    return NULL;
}

void
stats_destroy(struct stats *st)
{
    stats_stop_aggregator(st);
    stats_pool_unmap(&st->sum);
    stats_pool_unmap(&st->shadow);
    stats_pool_unmap(&st->current);
    stats_destroy_buf(st);
    nc_free(st);
}

void
stats_swap(struct stats *st)
{
    if (!stats_enabled) {
        return;
    }

    if (st->aggregate == 1) {
        log_debug(LOG_PVERB, "skip swap of current %p shadow %p as aggregator "
                  "is busy", st->current.elem, st->shadow.elem);
        return;
    }

    if (st->updated == 0) {
        log_debug(LOG_PVERB, "skip swap of current %p shadow %p as there is "
                  "nothing new", st->current.elem, st->shadow.elem);
        return;
    }

    log_debug(LOG_PVERB, "swap stats current %p shadow %p", st->current.elem,
              st->shadow.elem);

    array_swap(&st->current, &st->shadow);

    /*
     * Reset current (a) stats before giving it back to generator to keep
     * stats addition idempotent
     */
    stats_pool_reset(&st->current);
    st->updated = 0;

    st->aggregate = 1;
}

static struct stats_metric *
stats_pool_to_metric(struct context *ctx, struct server_pool *pool,
                     stats_pool_field_t fidx)
{
    struct stats *st;
    struct stats_pool *stp;
    struct stats_metric *stm;
    uint32_t pidx;

    pidx = pool->idx;

    st = ctx->stats;
    stp = array_get(&st->current, pidx);
    stm = array_get(&stp->metric, fidx);

    st->updated = 1;

    log_debug(LOG_VVVERB, "metric '%.*s' in pool %"PRIu32"", stm->name.len,
              stm->name.data, pidx);

    return stm;
}

void
_stats_pool_incr(struct context *ctx, struct server_pool *pool,
                 stats_pool_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter++;

    log_debug(LOG_VVVERB, "incr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_decr(struct context *ctx, struct server_pool *pool,
                 stats_pool_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter--;

    log_debug(LOG_VVVERB, "decr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_incr_by(struct context *ctx, struct server_pool *pool,
                    stats_pool_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter += val;

    log_debug(LOG_VVVERB, "incr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_decr_by(struct context *ctx, struct server_pool *pool,
                    stats_pool_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter -= val;

    log_debug(LOG_VVVERB, "decr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_pool_set_ts(struct context *ctx, struct server_pool *pool,
                   stats_pool_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_pool_to_metric(ctx, pool, fidx);

    ASSERT(stm->type == STATS_TIMESTAMP);
    stm->value.timestamp = val;

    log_debug(LOG_VVVERB, "set ts field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.timestamp);
}

static struct stats_metric *
stats_server_to_metric(struct context *ctx, struct server *server,
                       stats_server_field_t fidx)
{
    struct stats *st;
    struct stats_pool *stp;
    struct stats_server *sts;
    struct stats_metric *stm;
    uint32_t pidx, sidx;

    sidx = server->idx;
    pidx = server->owner->idx;

    st = ctx->stats;
    stp = array_get(&st->current, pidx);
    sts = array_get(&stp->server, sidx);
    stm = array_get(&sts->metric, fidx);

    st->updated = 1;

    log_debug(LOG_VVVERB, "metric '%.*s' in pool %"PRIu32" server %"PRIu32"",
              stm->name.len, stm->name.data, pidx, sidx);

    return stm;
}

void
_stats_server_incr(struct context *ctx, struct server *server,
                   stats_server_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter++;

    log_debug(LOG_VVVERB, "incr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_decr(struct context *ctx, struct server *server,
                   stats_server_field_t fidx)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter--;

    log_debug(LOG_VVVERB, "decr field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_incr_by(struct context *ctx, struct server *server,
                      stats_server_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_COUNTER || stm->type == STATS_GAUGE);
    stm->value.counter += val;

    log_debug(LOG_VVVERB, "incr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_decr_by(struct context *ctx, struct server *server,
                      stats_server_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_GAUGE);
    stm->value.counter -= val;

    log_debug(LOG_VVVERB, "decr by field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.counter);
}

void
_stats_server_set_ts(struct context *ctx, struct server *server,
                     stats_server_field_t fidx, int64_t val)
{
    struct stats_metric *stm;

    stm = stats_server_to_metric(ctx, server, fidx);

    ASSERT(stm->type == STATS_TIMESTAMP);
    stm->value.timestamp = val;

    log_debug(LOG_VVVERB, "set ts field '%.*s' to %"PRId64"", stm->name.len,
              stm->name.data, stm->value.timestamp);
}

void
stat_req_incr  (struct context *ctx, struct msg *pmsg)
{
	int32_t seg,i;
	int64_t t, diff;
	struct string *req_type = NULL;

	if (pmsg->recv_usec == 0) {
		 return;
	 }
	 t =  nc_usec_now();
         diff =   t- pmsg->recv_usec;

         ctx->req_stats[pmsg->type].calls ++;
	 ctx->req_stats[pmsg->type].microseconds += ( diff );

	 if (diff < 0) {
		 log_error ("get bad stat from client 1.1.1.1:xxxx msg_type mget");
		 return;
	 }

	 seg = NC_REQ_STAT_RANGER_MAX;
	 for (i=0;i<=NC_REQ_STAT_RANGER_MAX;i++) {
		 if (diff < ctx->range_stats[i].kus_end) {
			 seg = i;
			 break;
		 }
	 }

	 ctx->range_stats[seg].calls ++;
	 ctx->range_stats[seg].microseconds += ( diff );


	 if (ctx->slowms > 0 && diff >= ctx->slowms) {
            req_type = msg_type_string(pmsg->type);
            if(pmsg->keys != NULL && pmsg->keys->nelem >0 ){
                struct keypos * tmp_k = pmsg->keys->elem;
                uint32_t tmp_kl = (uint32_t)(tmp_k->end - tmp_k->start);
                log_debug(LOG_ERR, "slowquery %d slowms:%d msg_type:%d %.*s  start_ts %llu end_ts %llu seg:%d key:%.*s", diff, ctx->slowms, pmsg->type, req_type->len, req_type->data, pmsg->recv_usec, t,  seg, tmp_kl, tmp_k->start);
            }else{
                log_debug(LOG_ERR, "slowquery %d slowms:%d msg_type:%d %.*s  start_ts %llu end_ts %llu seg:%d", diff, ctx->slowms, pmsg->type, req_type->len, req_type->data, pmsg->recv_usec, t,  seg);
            }
	 }

}
