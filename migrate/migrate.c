/*
 * migrate: 将一个redis的所有KEY迁移到另外一个REDIS
 * 参数: migrate src-ip:port src-redis-pass  dst-ip:port to-redis-pass  100
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <unistd.h>
#include <assert.h>
#include <transfer.h>

#define CMD_MAX_LEN  100000
#define LOG_MAX_LEN 102400
#define MAX_THREAD_NUM 100
/* Hash buckets, fixed: 420000 */
#define REDIS_HASH_BUCKETS 420000 
static uint64_t FNV_64_INIT = UINT64_C(0xcbf29ce484222325);
static uint64_t FNV_64_PRIME = UINT64_C(0x100000001b3);
static uint32_t FNV_32_INIT = 2166136261UL;
static uint32_t FNV_32_PRIME = 16777619;
// global variables
static int32_t src_seg_start,src_seg_end;


uint32_t g_job_thread_num = 10;
uint32_t g_enable_conflit_key_num = 0;

#define trans_log(...) do {                                                      \
        _my_log(__FILE__, __LINE__,  __VA_ARGS__);                         \
} while (0)

void _my_log(const char *file, int line, const char *fmt, ...) {
	int len, size;
	char buf[LOG_MAX_LEN], *timestr;
	va_list args;
	struct tm local;
	time_t t;

	len = 0; /* length of output buffer */
	size = LOG_MAX_LEN; /* size of output buffer */

	t = time(NULL);
	localtime_r(&t, &local);
	timestr = asctime(&local);

	len += snprintf(buf + len, size - len, "[%.*s] %s:%d (%lu)", (int )strlen(timestr) - 1, timestr, file, line, (unsigned long)pthread_self());

	va_start(args, fmt);
	len += vsnprintf(buf + len, size - len, fmt, args);
	va_end(args);

	buf[len] = 0;

	write(STDOUT_FILENO, buf, len);

}


uint32_t
hash_fnv1a_64(const char *key, size_t key_length)
{
    uint32_t hash = (uint32_t) FNV_64_INIT;
    size_t x;

    for (x = 0; x < key_length; x++) {
        uint32_t val = (uint32_t)key[x];
        hash ^= val;
        hash *= (uint32_t) FNV_64_PRIME;
    }

    return hash; 
}
uint32_t get_key_hash(char * key, size_t len){

    uint32_t val = hash_fnv1a_64( key, len);
    val %= REDIS_HASH_BUCKETS;

    return val; 
}

int tcp_connect(char *ip, uint16_t port) {

	struct hostent *host;
	int sock;

	struct sockaddr_in server_addr;
	host = gethostbyname(ip);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket");
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	bzero(&(server_addr.sin_zero), 8);

	if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
		return -1;
	}

	return sock;
}

int do_proxy_cmd(int sock, char *cmd, char *buf, int buflen) {
	int n;
	n = send(sock, cmd, strlen(cmd), 0);
	if (n < 0) {

	} else if (n == (int) strlen(cmd)) {

	} else {

	}

	n = recv(sock, buf, buflen, 0);
	buf[n] = '\0';
	return n;
}

/*
 *
 */

//char redis_reply_name[][8] = { "", "STRING", "ARRAY", "INTEGER", "NIL", "STATUS", "ERROR" };
void print_reply_info_with_redisinfo(redisInfo * r, const char *cmd, redisReply * reply) {
	char ipportcmd[CMD_MAX_LEN];
	snprintf(ipportcmd, CMD_MAX_LEN, "%s:%d %s", r->host, r->port, cmd);
	print_reply_info(ipportcmd, reply);

}
/* print reply info*/
void print_reply_info(char *cmd, redisReply * reply) {
	size_t j;
	/*
	 * #define REDIS_REPLY_STRING 1
	 #define REDIS_REPLY_ARRAY 2
	 #define REDIS_REPLY_INTEGER 3
	 #define REDIS_REPLY_NIL 4
	 #define REDIS_REPLY_STATUS 5
	 #define REDIS_REPLY_ERROR 6
	 */
	if (!cmd || !reply) {
		trans_log("try to printf a empty cmd or reply\n");
		return;
	}

	trans_log("'%s'\t return len: %d type:%d elems:%zd str:'%s' value:'%d'\n", cmd, reply->len, reply->type, reply->elements, reply->str, reply->integer);

	switch (reply->type) {
	case REDIS_REPLY_INTEGER:

	case REDIS_REPLY_ERROR:
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_NIL:
		break;
	case REDIS_REPLY_STRING:
		/*if (reply->len > 0) {
		 for (int j=0;j<reply->len;j++) {
		 trans_log("%x:%c\n", j, *(reply->str + j));
		 }
		 trans_log("\n");
		 }*/
		break;
	case REDIS_REPLY_ARRAY:
		if (reply->type == REDIS_REPLY_ARRAY && reply->elements > 0) {
			for (j = 0; j < reply->elements; j++) {
				trans_log("[%zd] %s\n", j, reply->element[j]->str);
			}
		}
		break;

	default:
		;

	}

}

/*
 * trans_string.
 */
int trans_string(redisInfo *src, redisInfo *dst, char * keyname, int keyname_len) {
	redisReply *reply_set, *reply;
	char cmd[CMD_MAX_LEN];
	char * setcmd = NULL;
	long long ttl;

//	const char * key_locked = "locked";

//get ttl of key at src

	/* Starting with Redis 2.8 the return value in case of error changed:
	 The command returns -2 if the key does not exist.
	 The command returns -1 if the key exists but has no associated expire.
	 if 2.6 how ?
	 */

	//first check this key is in dst ?
	snprintf(cmd, CMD_MAX_LEN, "type \"%s\"", keyname);
	reply = redisCommand(dst->rd, "type %b", keyname, keyname_len);
	//print_reply_info(cmd, reply);
	if (!reply) {
		trans_log("ERR: do %s failed\n", cmd);
		return REDIS_ERR;
	}
	if (reply->len != 4 && strncmp(reply->str, "none", 4) != 0) {
		trans_log("ERROR, %s:%d a duplicate key found '%s'\n", src->host, src->port, keyname);
		freeReplyObject(reply);
		return REDIS_DUP;
	} else {
		freeReplyObject(reply);
	}

	snprintf(cmd, CMD_MAX_LEN, "pttl \"%s\"", keyname);
	reply = redisCommand(src->rd, "pttl %b", keyname, keyname_len);

	//print_reply_info(cmd, reply);
	// pttl result mayben null
	if (!reply) {
		trans_log("ERR: do %s failed\n", cmd);
		return REDIS_ERR;
	}

	ttl = reply->integer;
	if (ttl == -1) {
		// if no ttl set, here set it as 0
		ttl = 0;
	} else if (ttl == 0) {
		// if the ttl is 0, the key will expired ,here we add 1 ms for that key ? or just donot restore?
		ttl = 1;
	} else if (ttl == -2) {
		trans_log("info: key not found: %s \n", cmd);
		// key not exist, maybe ttl or deleted, got unlock.
		goto UNLOCK_KEY;
	}

	freeReplyObject(reply);

	//get value of key at src, dump return maybe nil
	snprintf(cmd, CMD_MAX_LEN, "dump %s", keyname);
	reply = redisCommand(src->rd, "dump %b", keyname, keyname_len);
	//print_reply_info(cmd, reply);
	if (!reply) {
		trans_log("ERR: do %s failed\n", cmd);
		return REDIS_ERR;
	}
	//print_reply_info(cmd, reply);

	if (reply->type == REDIS_REPLY_NIL) {
		trans_log("WARN: get the key %s failed, may be is expired\n", keyname);
	}
	//set to dst
	if (reply->type == REDIS_REPLY_STRING) {
		setcmd = malloc(reply->len + 1024); //1024 is enough

		// maybe very long.
		snprintf(setcmd, reply->len + 1024, "restore %s %lld ", keyname, ttl);
		reply_set = redisRestoreCommand(dst->rd, keyname, keyname_len, ttl, reply->str, reply->len);

		//print_reply_info(setcmd, reply_set);
		freeReplyObject(reply_set);
	} else {
		trans_log("ERR: do %s failed, return not a STRING\n", cmd);
	}

	if (setcmd)
		free(setcmd);
	if (reply)
		freeReplyObject(reply);

	UNLOCK_KEY:

	//TODO DEL  key at src
	/*
	snprintf(cmd, CMD_MAX_LEN, "del '%s'", keyname);
	reply = redisCommand(src->rd, "del %b", keyname, keyname_len);
	print_reply_info(cmd, reply);
	if (!reply) {
		trans_log("ERR: src %s failed\n", cmd);
		//return a fatal error;
	} else if (check_reply_ok_and_free(src, cmd, reply) != REDIS_OK) {
		trans_log("ERR: src %s failed\n", cmd);
		// return a work;
		return REDIS_ERR;
	}
	*/

	return REDIS_OK;


}

int docmd(redisInfo *r, const char *cmd) {
	redisReply * reply;
	reply = redisCommand(r->rd, cmd);
	if (!reply) {
		trans_log("%s:%d exec %s failed\n", r->host, r->port, cmd);
		return REDIS_ERR;
	} else {
		print_reply_info_with_redisinfo(r, cmd, reply);
		freeReplyObject(reply);
	}

	return REDIS_OK;
}

int check_reply_ok(redisReply * reply) {
	if (reply && reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "ok") == 0) {
		return REDIS_OK;
	}

	if (reply && reply->type == REDIS_REPLY_INTEGER && reply->integer == 1) {
		return REDIS_OK;
	}
	return REDIS_ERR;
}

int check_reply_nil(redisReply * reply) {
	if (reply && reply->type == REDIS_REPLY_NIL) {
		return REDIS_OK;
	}
	return REDIS_ERR;
}

int check_reply_status_str(redisReply * reply, const char * str) {
	if (reply && reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, str) == 0) {
		return REDIS_OK;
	}
	return REDIS_ERR;
}

void check_reply_and_free(redisReply * reply) {
	if (reply) {
		freeReplyObject(reply);
	}
	return;
}

int check_reply_ok_and_free(redisInfo *ri, const char * cmd, redisReply * reply) {
	int ret = check_reply_ok(reply);
	print_reply_info_with_redisinfo(ri, cmd, reply);
	check_reply_and_free(reply);
	return ret;
}

void* stats_thread(void *ptr) {
	return ptr;
}

void* dojob(void * ptr) {
	transInfo *t = (transInfo *) ptr;
	int status;

	pthread_mutex_lock(&t->job->mutex);

	//control threadnum to control the speed

	if (t->job->done || t->job->err) {
		pthread_mutex_unlock(&t->job->mutex);
		return 0;
	}

	pthread_mutex_unlock(&t->job->mutex);

	status = transfer_bucket(t);

	return 0;
}

void log_err(const char * errstr) {
	trans_log("[ ERROR ] at %s:%d ,err info: %s\n", __FILE__, __LINE__, errstr);
}

void log_info(const char * errstr) {
	trans_log("[ INFO ] at %s:%d ,info: %s\n", __FILE__, __LINE__, errstr);
}

int transfer_bucket(void * ptr) {
	/*
	 * 1, get the keys of src, require > 0
	 * 2, get the keys of dst , require 0
	 * 3,
	 */
	transInfo *t = (transInfo *) ptr;
	redisInfo *src, *dst;
	uint32_t bucketid;
	uint32_t processid;

	char *cmd = NULL;

	int keys_len, i, status;
	redisReply *keys; // store keys of bucket;
	redisReply *repl;


	src = &t->src;
	dst = &t->dst;

	processid = t->processid;
	keys = t->job->keys;

	assert(src->rd && dst->rd);
 	trans_log("transfer_bucket src %s:%d dst %s:%d processid %d .\nsegstart:%d ,sedend:%d \n", src->host, src->port, dst->host, dst->port, processid,src_seg_start,src_seg_end);

	keys_len = keys->elements;

	// process each key
	for (i = 0; i < keys_len; i++) {
		if (i % g_job_thread_num != processid) {
			continue;
		}

        int32_t keyhash = get_key_hash(keys->element[i]->str, keys->element[i]->len);
        if( keyhash < src_seg_start || keyhash > src_seg_end) {
            printf("keyhash is not ok, skip.  start: %d,end: %d. keyhash: %d\n",src_seg_start,src_seg_end,keyhash);
            continue;
        }
        status = trans_string(src, dst, keys->element[i]->str, keys->element[i]->len);
		trans_log("transkey '%s' return %d\n", keys->element[i]->str, status);


		if (REDIS_OK == status) {
			pthread_mutex_lock(&t->job->mutex);
			t->job->key_succ ++;
			pthread_mutex_unlock(&t->job->mutex);

		} else if (REDIS_DUP == status) {
			//dup ++
			pthread_mutex_lock(&t->job->mutex);
			t->job->key_fail ++;
			pthread_mutex_unlock(&t->job->mutex);
		}	else {
			pthread_mutex_lock(&t->job->mutex);
			t->job->key_fail ++;
			pthread_mutex_unlock(&t->job->mutex);

			trans_log("trans key '%s' failed @ thread:%d\n", keys->element[i]->str, processid);
			return REDIS_ERR;
		}

		if (t->job->key_fail >= t->job->key_fail_enable) {
			t->job->err = 1;
			trans_log("ERROR, trans key failed key over %d, stop\n",t->job->key_fail_enable);
			break;
		}
	}


	repl = NULL;


	return REDIS_OK;

	err:

	trans_log("thread:%d failed ERR\n", processid);

	return REDIS_ERR;
}

int _nc_atoi(unsigned char *line, size_t n) {
	int value;

	if (n == 0) {
		return -1;
	}

	for (value = 0; n--; line++) {
		if (*line < '0' || *line > '9') {
			return -1;
		}

		value = value * 10 + (*line - '0');
	}

	if (value < 0) {
		return -1;
	}

	return value;
}

int parse_ipport(const char* ipport, char *ip, uint32_t iplen, uint16_t * port) {
	char *p;
	int len;
	int len2;
	len2 = strlen(ipport);
	p = strchr(ipport, ':');
	if (!p) {
		return REDIS_ERR;
	}

	len = p - ipport;
	if (len >= (int) iplen) {
		len = iplen - 1;
	}
	strncpy(ip, ipport, len);
	ip[len] = '\0';

	*port = _nc_atoi((unsigned char *) (p + 1), len2 - len - 1);

	if (*port <= 0 || *port >= 65535) {
		return REDIS_ERR;
	}
	//dstDO check ip port

	return REDIS_OK;
}

int connect_redis(redisInfo * redis, char *hostname, uint16_t port, char * pass) {
	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redis->rd = redisConnectWithTimeout(hostname, port, timeout);
	if (redis->rd == NULL || redis->rd->err) {
		if (redis->rd) {
			trans_log("connect redis %s:%d errorno:%d, errstr:%s\n", hostname, port, redis->rd->err, redis->rd->errstr);
			redisFree(redis->rd);
		} else {
			trans_log("connect redis %s:%d error:can't allocate redis context\n", hostname, port);
		}
		return REDIS_ERR;
	}
	//trans_log("connect redis %s:%d succ %p\n", hostname, port, (void * )redis->rd);

	if (strlen(pass)>0) {
		redisReply  * reply;
		reply = redisCommand(redis->rd, "auth %s", pass);
		if (reply->len != 2 || strncmp (reply->str , "OK", 2) != 0) {
			trans_log("connect redis %s:%d using pass '%s' failed\n", hostname, port, pass);
			redisFree(redis->rd);
			return REDIS_ERR;
		}
	}


	redis->port = port;
	strncpy(redis->host, hostname, sizeof(redis->host));
	return REDIS_OK;
}

int parse_proxylist(char *filename, redisInfo *proxylist) {
	int n, status, pos, proxy_num;
	char buf[32];
	char ch;
	FILE *fh = fopen(filename, "r");
	if (!fh) {
		trans_log("open proxylist:%s failed\n", filename);
		return 0;
	}

	proxy_num = 0;
	n = 0;
	ch = fgetc(fh);
	pos = 0;
	while (1) {
		buf[n++] = ch;
		pos++;
		if (ch == '\n' || ch == EOF) {
			if (n == 1) {
				if (ch == EOF) {
					//end of file
					break;
				} else {
					trans_log("parse twemproxy-list %s faild , a empty line found\n", filename);
					return 0;
				}
			}

			buf[n - 1] = '\0';
			status = parse_ipport(buf, proxylist[proxy_num].host, sizeof(proxylist[proxy_num].host), &proxylist[proxy_num].port);
			if (status == REDIS_ERR) {
				trans_log("parse proxylist:%s:%d failed '%s'\n", filename, n, buf);
				return 0;
			} else {
				proxy_num++;
			}

			if (ch == EOF) {
				break;
			}
			n = 0;
		}
		ch = fgetc(fh);
	}

	fclose(fh);
	return proxy_num;

}


int main(int argc, char **argv) {
	int status, n;

	char src_host[32], dst_host[32];
	char * src_passwd;
	char * dst_passwd;
	uint16_t src_port, dst_port;
	int32_t seg_start, seg_end, idx, keys_todo;
	uint32_t i;

	jobQueue job;
	bucketInfo * bucketlist;
	bucketInfo * thlist;

	pthread_t thrd[MAX_THREAD_NUM];
	pthread_t stats_thrd;
	transInfo task[MAX_THREAD_NUM];

	char redis_cmd[CMD_MAX_LEN];

	g_enable_conflit_key_num = 0;

	redisReply * reply;
	redisReply * keys;




    // init as 0~420000
	seg_start = 0;
	seg_end = 420000;

	if (argc != 8) {
		printf("transfer: bad arg number %d\n", argc);
		printf("usage: migrate   src-redis:port src-redis-pass dst-redis:port dst-redis-pass enable-duplicate-key-num src_seg_start src_seg_end\n\n");
		exit(1);
	}

	status = parse_ipport(argv[1], src_host, sizeof(src_host), &src_port);
	if (status == REDIS_ERR) {
		trans_log("transfer: bad srcip:%s", argv[4]);
		exit(1);
	}

	status = parse_ipport(argv[3], dst_host, sizeof(dst_host), &dst_port);
	if (status == REDIS_ERR) {
		trans_log("transfer: bad dstip:%s", argv[5]);
		exit(1);
	}

	src_passwd = argv[2];
	dst_passwd = argv[4];

	if (strlen(argv[5]) > 0) {
		g_enable_conflit_key_num = _nc_atoi((unsigned char *) argv[5], strlen(argv[5]));
	}

	if (strlen(argv[6]) > 0) {
		src_seg_start = _nc_atoi((unsigned char *) argv[6], strlen(argv[6]));
	}

	if (strlen(argv[7]) > 0) {
		src_seg_end = _nc_atoi((unsigned char *) argv[7], strlen(argv[7]));
	}

	trans_log("args:src host %s\n", argv[1]);
	trans_log("args:dst host %s\n", argv[3]);
	trans_log("args:enable conflit key num to %s\n", argv[5]);


	job.done = 0;
	pthread_mutex_init(&job.mutex, NULL);
	job.err = 0;

	trans_log("transfer: got args %s : %d %s : %d %d %d\n", src_host, src_port, dst_host, dst_port, src_seg_start, src_seg_end);

	for (i = 0; i < MAX_THREAD_NUM; i++) {
		task[i].src.rd = NULL;
		task[i].dst.rd = NULL;
	}

	//init redis handle
	for (i = 0; i < MAX_THREAD_NUM; i++) {
		status = connect_redis(&task[i].src, src_host, src_port, src_passwd);
		if (status != REDIS_OK) {
			task[i].src.rd = NULL;
			trans_log("[thread %d] conn src redis %s:%d:'%s' failed\n", i, src_host, src_port, src_passwd);
			goto end;
		}

		//docmd(&task[i].src, "PING");

		status = connect_redis(&task[i].dst, dst_host, dst_port, dst_passwd);
		if (status != REDIS_OK) {
			task[i].dst.rd = NULL;
			trans_log("[thread %d] conn src redis %s:%d:'%s' failed\n", i, dst_host, dst_port, dst_passwd);
			goto end;
		}

		//docmd(&task[i].dst, "PING");

		task[i].processid = i;
		task[i].job = &job;

	}

	//src: get keys
	snprintf(redis_cmd, CMD_MAX_LEN, "keys *");
	keys = redisCommand(task[0].src.rd, redis_cmd);

	if (!keys) {
		trans_log("%s:%d:%s get keys failed\n", src_host, src_port, src_passwd);
		log_info(redis_cmd);
		goto end;
	}

//	job.key_num = keys->elements;
	job.key_fail = 0;
	job.key_fail_enable = g_enable_conflit_key_num;
 	job.key_succ = 0;


	trans_log("%s:%d:%s keys number is %d\n", src_host, src_port, src_passwd, keys->elements);

	if (keys->elements <= 0) {
		trans_log("keys number is 0, nothing to migrate, exit\n");
		goto end;
	}

	job.keys = keys;

	for (i = 0; i < g_job_thread_num; i++) {
//		trans_log("start a thread %d\n", task[i].processid);
		pthread_create(&thrd[i], NULL, dojob, (void *) &task[i]);
	}

	//	pthread_create(&stats_thrd, NULL, stats_thread, (void *) &task[0]);

	for (i = 0; i < g_job_thread_num; i++) {
		pthread_join(thrd[i], NULL);
	}

	//pthread_join(stats_thrd, NULL);

	keys_todo = job.keys->elements - job.key_succ - job.key_fail;
	trans_log ("TRANSFER_DONE: src %s:%d dst %s:%d keynum:%d succ:%d failed:%d err:%d todo:%d\n",
			src_host, src_port, dst_host, dst_port,
			job.keys->elements, job.key_succ, job.key_fail, job.err,  keys_todo);

	if (job.err) {
		log_err("ERROR: transfering some error happened, transfer failed, trans job not finished,exit.\n");
		exit(1);
	}

	end:
	//disconnect redis
	for (i = 0; i < MAX_THREAD_NUM; i++) {
		if (task[i].src.rd)
			redisFree(task[i].src.rd);	//if not connect && free , OK?
		if (task[i].dst.rd)
			redisFree(task[i].dst.rd);
	}
	return 0;
}
