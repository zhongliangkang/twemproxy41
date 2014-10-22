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

uint32_t g_job_thread_num = 100;

#define trans_log(...) do {                                                      \
        _my_log(__FILE__, __LINE__,  __VA_ARGS__);                         \
} while (0)

void _my_log(const char *file, int line, const char *fmt, ...) {
	int len, size;
	char buf[LOG_MAX_LEN], *timestr;
	va_list args;
	struct tm *local;
	time_t t;

	len = 0; /* length of output buffer */
	size = LOG_MAX_LEN; /* size of output buffer */

	t = time(NULL);
	local = localtime(&t);
	timestr = asctime(local);

	len += snprintf(buf + len, size - len, "[%.*s] %s:%d ", (int )strlen(timestr) - 1, timestr, file, line);

	va_start(args, fmt);
	len += vsnprintf(buf + len, size - len, fmt, args);
	va_end(args);

	buf[len] = 0;

	write(STDOUT_FILENO, buf, len);

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

char redis_reply_name[][8] = { "", "STRING", "ARRAY", "INTEGER", "NIL", "STATUS", "ERROR" };

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

	trans_log("'%s'\t return len: %d type:%d elems:%zd str:'%s'\n", cmd, reply->len, reply->type, reply->elements, reply->str);

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
	const char * key_locked = "locked";

	// rclock key at dst
	snprintf(cmd, CMD_MAX_LEN, "rclockkey \"%s\"", keyname);
	reply = redisCommand(dst->rd, "rclockkey %b", keyname, keyname_len);

	if (check_reply_status_str(reply, key_locked) == REDIS_OK) {
		// key is locking in dest. how to do?
		check_reply_and_free(reply);
	} else if (check_reply_ok_and_free(dst, cmd, reply) != REDIS_OK) {
		trans_log("ERR: dst lockkey %s failed\n", cmd);
		goto ERROR_UNLOCK_KEY;
	}

	//rclock ok  or key is locking.

	// rclock key at src
	reply = redisCommand(src->rd, "rclockkey %b", keyname, keyname_len);

	if (check_reply_status_str(reply, key_locked) == REDIS_OK) {
		// key is locking in dest. how to do?
		check_reply_and_free(reply);
	} else if (check_reply_ok_and_free(src, cmd, reply) != REDIS_OK) {
		trans_log("ERR: src lockkey %s failed\n", cmd);
		goto ERROR_UNLOCK_KEY;
	}

	// rclock ok or key is locking.

	//get ttl of key at src

	/* Starting with Redis 2.8 the return value in case of error changed:
	 The command returns -2 if the key does not exist.
	 The command returns -1 if the key exists but has no associated expire.
	 */
	snprintf(cmd, CMD_MAX_LEN, "pttl \"%s\"", keyname);
	reply = redisCommand(src->rd, "pttl %b", keyname, keyname_len);

	print_reply_info(cmd, reply);
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
	print_reply_info(cmd, reply);
	if (!reply) {
		trans_log("ERR: do %s failed\n", cmd);
		return REDIS_ERR;
	}
	print_reply_info(cmd, reply);

	if (reply->type == REDIS_REPLY_NIL) {
		trans_log("WARN: get the key %s failed, may be is expired\n", keyname);
	}
	//set to dst
	if (reply->type == REDIS_REPLY_STRING) {
		setcmd = malloc(reply->len + 1024); //1024 is enough

		// maybe very long.
		snprintf(setcmd, reply->len + 1024, "restore %s %lld ", keyname, ttl);
		reply_set = redisRestoreCommand(dst->rd, keyname, keyname_len, ttl, reply->str, reply->len);

		print_reply_info(setcmd, reply_set);
		freeReplyObject(reply_set);
	} else {
		trans_log("ERR: do %s failed, return not a STRING\n", cmd);
	}

	if (setcmd)
		free(setcmd);
	if (reply)
		freeReplyObject(reply);

	//TODO  set pexpire if pttl > 0

	UNLOCK_KEY:

	// rcunlock key at dst. dst cannot be error!
	snprintf(cmd, CMD_MAX_LEN, "rcunlockkey %s", keyname);
	reply = redisCommand(dst->rd, "rcunlockkey %b", keyname, keyname_len);
	if (!reply) {
		trans_log("ERR: %s failed\n", cmd);
		goto ERROR_UNLOCK_KEY;
	} else if (check_reply_ok_and_free(dst, cmd, reply) != REDIS_OK) {
		trans_log("ERR: dst lockkey %s failed\n", cmd);
		goto ERROR_UNLOCK_KEY;
	}

	// unlock key at src, maybe fail
	snprintf(cmd, CMD_MAX_LEN, "rctransendkey %s", keyname);
	//TODO rclock key at src
	reply = redisCommand(src->rd, "rctransendkey %b", keyname, keyname_len);
	if (!reply) {
		trans_log("ERR: %s failed\n", cmd);
	} else if (check_reply_ok_and_free(src, cmd, reply) != REDIS_OK) {
		trans_log("ERR: src lockkey %s failed\n", cmd);
	}

	return REDIS_OK;

	ERROR_UNLOCK_KEY:
	// rcunlock key at dst. dst cannot be error!
	snprintf(cmd, CMD_MAX_LEN, "rcunlockkey %s", keyname);
	reply = redisCommand(dst->rd, "rcunlockkey %b", keyname, keyname_len);
	if (!reply) {
		trans_log("ERROR_UNLOCK_KEY unlock dst : %s reply is null\n", cmd);
	} else if (check_reply_ok_and_free(dst, cmd, reply) != REDIS_OK) {
		trans_log("ERROR_UNLOCK_KEY unlock dst : %s failed\n", cmd);
	}

	//TODO rclock key at src
	reply = redisCommand(src->rd, "rcunlockkey %b", keyname, keyname_len);
	if (!reply) {
		trans_log("ERROR_UNLOCK_KEY unlock src : %s reply is null\n", cmd);
	} else if (check_reply_ok_and_free(src, cmd, reply) != REDIS_OK) {
		trans_log("ERROR_UNLOCK_KEY unlock src : %s failed\n", cmd);
	}

	return REDIS_ERR;
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
	transInfo *t = (transInfo *) ptr;

	int seg_num = 0;


	int seg_undone = 0;
	seg_num = t->job->seg_end - t->job->seg_start + 1;
	int keys_succ[2] = {0,0};
	int keys_fail[2] = {0,0};
	bucketInfo * tbucket;

	while (1) {
		keys_succ[0] = 0;
		keys_fail[0] = 0;

		keys_succ[1] = keys_succ[0];
		keys_fail[1] = keys_fail[0];

		for(int i=0;i<t->job->seg_curr-t->job->seg_start;i++) {
			tbucket = &t->job->bucketlist[i];
			keys_succ[0] += tbucket->key_succ;
			keys_fail[0] +=  tbucket->key_fail;
		}

		trans_log ("PROCESS seg_start:%d seg_end:%d todo:%d doing:%d done:%d SPEED: %d/s\n",
				t->job->seg_start, t->job->seg_end, seg_undone, t->job->seg_doing, t->job->seg_done, keys_succ[0]-keys_succ[1]);

		if (t->job->done || t->job->err) {
			break;
		}
		sleep (1);
	}

	return NULL;
}

void* dojob(void * ptr) {
	transInfo *t = (transInfo *) ptr;
	int status;

	while (1) {
		pthread_mutex_lock(&t->job->mutex);

		//control threadnum to control the speed


		if (t->job->done || t->job->err) {
			pthread_mutex_unlock(&t->job->mutex);
			break;
		}

		if (t->processid >= g_job_thread_num) {
			pthread_mutex_unlock(&t->job->mutex);
			sleep(2);
			continue;

		}

		t->bucket = &t->job->bucketlist[t->job->seg_curr - t->job->seg_start];

		assert(t->bucket->status == BUCKET_STATUS_TODO);
		assert(t->job->seg_curr <= t->job->seg_end && t->job->seg_start <= t->job->seg_curr);

		t->bucket->status = BUCKET_STATUS_DOING;
		t->job->seg_doing ++;

		if (t->job->seg_end == t->job->seg_curr) {
			t->job->done = 1;
		}
		t->job->seg_curr++;

		pthread_mutex_unlock(&t->job->mutex);

		status = transfer_bucket(t);
		if (status != REDIS_OK) {
			//TODO
			pthread_mutex_lock(&t->job->mutex);

			// error found.
			t->job->err = 1;
			pthread_mutex_unlock(&t->job->mutex);
		}

		pthread_mutex_lock(&t->job->mutex);
		t->bucket->status = BUCKET_STATUS_DONE;
		t->job->seg_doing --;
		t->job->seg_done ++;
		pthread_mutex_unlock(&t->job->mutex);

	}
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
	int bucketid;
//	char cmd[CMD_MAX_LEN];
	char *cmd = NULL;

	int keys_len, i, n, status;
	redisReply *keys; // store keys of bucket;
	redisReply *repl, *repl2;
	char *keyname = NULL;

	const char *bucket_transfering = "transfering";


	src = &t->src;
	dst = &t->dst;
	bucketid = t->bucket->bucket_id;

	/*
	 //for test
	 if(bucketid == 419999 ){
	 fprintf(stderr,"now process bucket 419999. sleep 100.\n");
	 sleep(10);
	 }
	 */

	assert(src->rd && dst->rd);
	assert(bucketid >=0 || bucketid < MODHASH_TOTAL_KEY);

	cmd = malloc(CMD_MAX_LEN);
	if (! cmd) {
		trans_log("malloc %d bytes error\n", CMD_MAX_LEN);
	}

	trans_log("transfer_bucket src %s:%d dst %s:%d bucket %d \n", src->host, src->port, dst->host, dst->port, bucketid);

	repl = redisCommand(src->rd, "rctransserver out");

	if (check_reply_ok_and_free(src, "rctransserver out", repl) != REDIS_OK) {
		log_info("rctransserver out");
		goto err;
	}

	repl = redisCommand(dst->rd, "rctransserver in");
	if (check_reply_ok_and_free(dst, "rctransserver in", repl) != REDIS_OK) {
		trans_log("trans in failed: %d\n", bucketid);
		log_info("rctransserver in");
		goto err;
	}

	n = snprintf(cmd, CMD_MAX_LEN, "rctransbegin %d %d", bucketid, bucketid);

	repl = redisCommand(src->rd, cmd);

	if (check_reply_status_str(repl, bucket_transfering) == REDIS_OK) {
		// bucket is locking in src. how to do?
		log_info("bucket is locking in src");
		check_reply_and_free(repl);
	} else if (check_reply_ok_and_free(src, cmd, repl) != REDIS_OK) {
		trans_log("transbegin src failed: %d\n", bucketid);
		log_info(cmd);
		goto err;
	}

	repl = redisCommand(dst->rd, cmd);
	if (check_reply_status_str(repl, bucket_transfering) == REDIS_OK) {
		// bucket is locking in src. how to do?
		log_info("bucket is locking in dst");
		check_reply_and_free(repl);
	} else if (check_reply_ok_and_free(dst, cmd, repl) != REDIS_OK) {
		trans_log("transbegin dst failed: %d\n", bucketid);
		log_info(cmd);
		goto err;
	}

	// check if there is locking key src
	snprintf(cmd, CMD_MAX_LEN, "rcgetlockingkey %d", bucketid);
	repl = redisCommand(src->rd, cmd);

	if (check_reply_nil(repl) == REDIS_OK) {
		check_reply_and_free(repl);  // nil, no key locking
	} else if (repl && repl->type == REDIS_REPLY_STRING) {
		trans_log("src locking key found: '%s' ,bucketid: %d\n", repl->str, bucketid);
		// key found, unlock it.
		snprintf(cmd, CMD_MAX_LEN, "rcunlockkey \"%s\"", repl->str);

		// TODO: if we need to check again here?!  maybe need.
		repl2 = redisCommand(src->rd, "rcunlockkey %b", repl->str, repl->len);
		if (check_reply_ok_and_free(src, cmd, repl2) != REDIS_OK) {
			log_info(cmd);
			trans_log("rcunlockkey src failed: %d\n", bucketid);

			check_reply_and_free(repl);
			goto err;
		}

		// free repl
		check_reply_and_free(repl);
	} else {
		// error return.
		log_info(cmd);
		trans_log("rcgetlockingkey error returned: '%s' ,bucketid: %d\n", repl->str, bucketid);
		goto err;
	}

	// check if there is locking key dst
	snprintf(cmd, CMD_MAX_LEN, "rcgetlockingkey %d", bucketid);
	repl = redisCommand(dst->rd, cmd);

	if (check_reply_nil(repl) == REDIS_OK) {
		check_reply_and_free(repl);  // nil, no key locking
	} else if (repl && repl->type == REDIS_REPLY_STRING) {
		trans_log("dst locking key found: '%s' ,bucketid: %d\n", repl->str, bucketid);
		// key found, unlock it.
		snprintf(cmd, CMD_MAX_LEN, "rcunlockkey \"%s\"", repl->str);

		// TODO: if we need to check again here?!  maybe need.
		repl2 = redisCommand(dst->rd, "rcunlockkey %b", repl->str, repl->len);
		if (check_reply_ok_and_free(dst, cmd, repl2) != REDIS_OK) {
			log_info(cmd);
			trans_log("rcunlockkey dst failed: %d\n", bucketid);

			check_reply_and_free(repl);
			goto err;
		}

		// free repl
		check_reply_and_free(repl);
	} else {
		// error return.
		log_info(cmd);
		trans_log("rcgetlockingkey error returned: '%s' ,bucketid: %d\n", repl->str, bucketid);
		goto err;
	}

	// get all the keys to transfer from src.
	snprintf(cmd, CMD_MAX_LEN, "hashkeys %d *", bucketid);
	keys = redisCommand(src->rd, cmd);

	print_reply_info(cmd, keys);
	if (!keys) {
		//todo add a check
		trans_log("cannot find keys: %d\n", bucketid);
		log_info(cmd);
		goto err;
	}
	keys_len = keys->elements;
	t->bucket->key_num = keys->elements;

	// process each key
	for (i = 0; i < keys_len; i++) {

		status = trans_string(src, dst, keys->element[i]->str, keys->element[i]->len);

		if (REDIS_OK == status) {
			t->bucket->key_succ++;
		} else {
			trans_log("trans string failed: %d\n", bucketid);
			t->bucket->key_fail++;
		}
	}

	if (keyname) {
		free(keyname);
	}

	freeReplyObject(keys);

	n = snprintf(cmd, CMD_MAX_LEN, "rctransend %d %d", bucketid, bucketid);
	repl = redisCommand(src->rd, cmd);
	if (check_reply_ok_and_free(src, cmd, repl) != REDIS_OK) {
		trans_log("trans end failed: %d\n", bucketid);
		log_info(cmd);
		goto err;
	}

	repl = redisCommand(dst->rd, cmd);
	if (check_reply_ok_and_free(dst, cmd, repl) != REDIS_OK) {
		trans_log("trans end dst failed: %d\n", bucketid);
		log_info(cmd);
		goto err;
	}

	repl = NULL;

	if (cmd)
		free(cmd);

	return REDIS_OK;

	err:
	if (cmd)
		free(cmd);
	trans_log("trans string failed ERR: %d\n", bucketid);

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

	*port = _nc_atoi((unsigned char *)(p + 1), len2 - len - 1);

	if (*port <= 0 || *port >= 65535) {
		return REDIS_ERR;
	}
	//dstDO check ip port

	return REDIS_OK;
}

int connect_redis(redisInfo * redis, char *hostname, uint16_t port) {
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
	trans_log("connect redis %s:%d succ %p\n", hostname, port, (void * )redis->rd);
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
	char *poolname, *app;
	char src_host[32], dst_host[32];
	uint16_t src_port, dst_port;
	int32_t seg_start, seg_end, i, idx;

	jobQueue job;
	bucketInfo * bucketlist;

	pthread_t thrd[MAX_THREAD_NUM];
	pthread_t stats_thrd;
	transInfo task[MAX_THREAD_NUM];

	char add_cmd[CMD_MAX_LEN], add_buf[CMD_MAX_LEN], redis_cmd[CMD_MAX_LEN];

	g_job_thread_num = 10;

	redisReply * reply;

	redisInfo proxylist[100];
	int proxylist_len = 0;

	if (argc != 8) {
		printf("transfer: bad arg\n");
		printf ("usage: transfer twemproxy-list poolname app src dst seg_start seg_end\n\n");
		printf("example: transfer twemproxy-list nosqlproxy pvz1 1.1.1.1:6379 1.1.1.1:6380 0 210000\n\n");
		exit(1);
	}

	proxylist_len = parse_proxylist(argv[1], proxylist);
	if (0 == proxylist_len) {
		trans_log("transfer: bad twemproxy-list:%s\n", argv[1]);
		exit(1);
	}

	poolname = argv[2];
	app = argv[3];

	status = parse_ipport(argv[4], src_host, sizeof(src_host), &src_port);
	if (status == REDIS_ERR) {
		trans_log("transfer: bad srcip:%s", argv[4]);
		exit(1);
	}

	status = parse_ipport(argv[5], dst_host, sizeof(dst_host), &dst_port);
	if (status == REDIS_ERR) {
		trans_log("transfer: bad dstip:%s", argv[5]);
		exit(1);
	}

	seg_start = atoi(argv[6]);
	seg_end = atoi(argv[7]);

	if (seg_start < 0 || seg_start >= MODHASH_TOTAL_KEY) {
		trans_log("transfer: bad seg_start:%s", argv[6]);
		exit(1);
	}

	if (seg_end < 0 || seg_end >= MODHASH_TOTAL_KEY) {
		trans_log("transfer: bad seg_end:%s", argv[7]);
		exit(1);
	}

	if (seg_end < seg_start) {
		trans_log("transfer: require seg_start <= seg_end: %s  %s", argv[6], argv[7]);
		exit(1);
	}

	//check twemproxy login ok
	//check redis login ok
	//

	//init bucketlist
	bucketlist = malloc(sizeof(bucketInfo) * (seg_end - seg_start + 1));
	for (i = seg_start; i <= seg_end; i++) {
		idx = i - seg_start;
		bucketlist[idx].bucket_id = i;
		bucketlist[idx].status = BUCKET_STATUS_TODO;
		bucketlist[idx].key_succ = 0;
		bucketlist[idx].key_fail = 0;
		bucketlist[idx].key_num = 0;
	}

	job.done = 0;
	pthread_mutex_init(&job.mutex, NULL);
	job.seg_start = seg_start;
	job.seg_end = seg_end;
	job.seg_curr = seg_start;
	job.seg_done = 0;
	job.seg_doing = 0;
	job.err = 0;
	job.bucketlist = bucketlist;

	trans_log("transfer: got args %s : %d %s : %d %d %d\n", src_host, src_port, dst_host, dst_port, seg_start, seg_end);

	for (i = 0; i < MAX_THREAD_NUM; i++) {
		task[i].src.rd = NULL;
		task[i].dst.rd = NULL;
	}

	//init redis handle
	for (i = 0; i < MAX_THREAD_NUM; i++) {
		status = connect_redis(&task[i].src, src_host, src_port);
		if (status != REDIS_OK) {
			task[i].src.rd = NULL;
			trans_log("[thread %d] conn src redis %s:%d failed\n", i, src_host, src_port);
			goto end;
		}

		//docmd(&task[i].src, "PING");

		status = connect_redis(&task[i].dst, dst_host, dst_port);
		if (status != REDIS_OK) {
			task[i].dst.rd = NULL;
			trans_log("[thread %d] conn src redis %s:%d failed\n", i, dst_host, dst_port);
			goto end;
		}

		//docmd(&task[i].dst, "PING");

		task[i].processid = i;
		task[i].job = &job;

	}
/*
 * 127.0.0.1:30000 pvz1 0-419999 1
 */


	//check twemproxy include old server
	for (i = 0; i < proxylist_len; i++) {
		int sock = tcp_connect(proxylist[i].host, proxylist[i].port + 1000);
		if (sock < 0) {
			trans_log("check twemproxy: connect to twemproxy %s:%d failed, exit\n", proxylist[i].host, proxylist[i].port + 1000);
			goto end;
		}

		n = snprintf(add_cmd, CMD_MAX_LEN, "get %s servers", poolname);
		add_cmd[n] = '\0';
		trans_log("cmd %s\n", add_cmd);

		char *s, *p;
		int matched = 0;
		char matchbuf_host[20], matchbuf_app[100];
		int matchbuf_port = 0, matchbuf_status = 0, matchbuf_seg_start = 0 , matchbuf_seg_end = 0;

		n = do_proxy_cmd(sock, add_cmd, add_buf, 1024);

		if (n <= 0) {
			trans_log("check twemproxy <%s:%d> FAIL, return NULL\n", proxylist[i].host, proxylist[i].port + 1000);
			goto end;
		}
//127.0.0.1:30000 pvz1 0-419999 1
		s = p = add_buf;
		while ( p - add_cmd < n) {
			if (*p == '\n') {
				*p = '\0';
				int sn = sscanf (s, "%[^:]:%d %s %d-%d %d", matchbuf_host, &matchbuf_port, matchbuf_app, &matchbuf_seg_start, &matchbuf_seg_end, &matchbuf_status);
				if (sn == 6) {
					if (0 == strcmp(matchbuf_host, src_host)
							&& matchbuf_port == src_port
							&& 0 == strcmp(matchbuf_app, app)
							&& matchbuf_status == 1
							&& matchbuf_seg_start <= seg_start
							&& matchbuf_seg_end >= seg_end
					) {
						matched = 1;
						s = p+1;
					}
				}

			}

			p++;

		}



		close(sock);

		if (matched == 0) {
			trans_log("check twemproxy <%s:%d> FAIL, servers not include %s:%d\n", proxylist[i].host, proxylist[i].port + 1000, src_host, src_port);
			goto end;
		} else {
			trans_log("check twemproxy <%s:%d> OK\n", proxylist[i].host, proxylist[i].port + 1000);
		}
	}

	//send_twemproxy_ add command
	for (i = 0; i < proxylist_len; i++) {
		int sock = tcp_connect(proxylist[i].host, proxylist[i].port + 1000);
		if (sock < 0) {
			trans_log("add: connect to twemproxy %s:%d failed, stop transing\n", proxylist[i].host, proxylist[i].port + 1000);
			goto end;
		}

		n = snprintf(add_cmd, CMD_MAX_LEN, "add %s %s:%d %s %d-%d", poolname, dst_host, dst_port, app, seg_start, seg_end);
		add_cmd[n] = '\0';
		trans_log("cmd %s\n", add_cmd);
		n = do_proxy_cmd(sock, add_cmd, add_buf, 1024);

		close(sock);

		if (strncmp(add_buf, "OK", 2)) {
			trans_log("add fail<%s>\n", add_buf);
			goto end;
		} else {
			trans_log("add succ<%s>\n", add_buf);
		}
	}


	for (i = 0; i < MAX_THREAD_NUM; i++) {
		pthread_create(&thrd[i], NULL, dojob, (void *) &task[i]);
	}

 	pthread_create(&stats_thrd, NULL, stats_thread, (void *) &task[0]);

	for (i = 0; i < MAX_THREAD_NUM; i++) {
		pthread_join(thrd[i], NULL);
	}

 	pthread_join(stats_thrd, NULL);

	// error happed when transfering, stop here!
	if (job.err) {
		log_err("ERROR: transfering some error happened, transfer failed, trans job not finished,exit.\n");
		exit(1);
	}

	/* if this bucket is the last bucket, we should run rccastransend to check if all the bucket transfered.
	 here we consider maybe rccastransend would return a error result if the redis is transfer 2 segment the same time.
	 but we donot look it as fail, but we give a warning that there maybe another transfer running on that redis.

	 so we just run rccastransend and record it's feedback.
	 */
	// run rccastransend src
	snprintf(redis_cmd, CMD_MAX_LEN, "rccastransend");

	// here we use the src/dst sock of task[0], it should be ok.
	reply = redisCommand(task[0].src.rd, redis_cmd);

	if (check_reply_ok_and_free(&task[0].src, redis_cmd, reply) != REDIS_OK) {
		log_err("src rccastransend error.");
	} else {
		log_info("src rccastransend OK.");
	}

	// run rccastransend dst
	reply = redisCommand(task[0].dst.rd, redis_cmd);

	if (check_reply_ok_and_free(&task[0].dst, redis_cmd, reply) != REDIS_OK) {
		log_err("dst rccastransend error.");
	} else {
		log_info("dst rccastransend OK.");
	}

	//send_twemproxy_ add command
	for (i = 0; i < proxylist_len; i++) {
		int sock = tcp_connect(proxylist[i].host, proxylist[i].port + 1000);
		if (sock < 0) {
			trans_log("adddone: connect to twemproxy %s:%d failed, next\n", proxylist[i].host, proxylist[i].port + 1000);
			continue;
		}

		n = snprintf(add_cmd, CMD_MAX_LEN, "adddone %s %s:%d %s %d-%d", poolname, dst_host, dst_port, app, seg_start, seg_end);
		add_cmd[n] = '\0';
		trans_log("cmd %s\n", add_cmd);
		n = do_proxy_cmd(sock, add_cmd, add_buf, 1024);
		trans_log("return <%s>", add_buf);
		close(sock);
	}

	end:
	//disconnect redis
	for (i = 0; i < MAX_THREAD_NUM; i++) {
		if (task[i].src.rd) redisFree(task[i].src.rd);	//if not connect && free , OK?
		if (task[i].dst.rd) redisFree(task[i].dst.rd);
	}
	return 0;
}
