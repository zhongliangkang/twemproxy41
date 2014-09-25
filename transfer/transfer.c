#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <assert.h>
#include <transfer.h>


int tcp_connect (char *ip, uint16_t port) {

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

int do_proxy_cmd (int sock, char *cmd, char *buf, int buflen) {
	int n;


	n = send(sock, cmd, strlen(cmd), 0);
	if (n < 0 ) {

	} else if (n == (int)strlen(cmd)) {

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

void print_reply_info_with_redisinfo (redisInfo * r, const char *cmd, redisReply * reply) {
	char ipportcmd [1024];
	snprintf (ipportcmd, 1024, "%s:%d %s", r->host, r->port, cmd);
	print_reply_info(ipportcmd,   reply);

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
	if (! cmd || ! reply) {
		printf ("try to printf a empty cmd or reply\n");	
		return ;
	}	


	printf("'%s'\t return len: %d type:%d(%s) elems:%zd str:'%s'\n", cmd, reply->len, reply->type,
						redis_reply_name[reply->type], reply->elements, reply->str);


	switch (reply->type) {
	case REDIS_REPLY_INTEGER:

	case REDIS_REPLY_ERROR:
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_NIL:
		break;
	case REDIS_REPLY_STRING:
		/*if (reply->len > 0) {
			for (int j=0;j<reply->len;j++) {
				printf ("%x:%c\n", j, *(reply->str + j));
			}
			printf ("\n");
		}*/
		break;
	case REDIS_REPLY_ARRAY:
		if (reply->type == REDIS_REPLY_ARRAY && reply->elements > 0) {
			for (j = 0; j < reply->elements; j++) {
				printf("[%zd] %s\n", j, reply->element[j]->str);
			}
		}
		break;

	default:
		;

	}

}


/*
 * trans_string
 */
int trans_string(redisInfo *src, redisInfo *dst, char * keyname) {
	redisReply    *reply_set, *reply;
	char cmd[100];
	char * setcmd = NULL;
	long long ttl;


	//TODO rclock key at dst
	snprintf(cmd, 100, "rclockkey %s", keyname);

	reply = redisCommand(dst->rd, cmd);
	if (!reply) {
		printf("ERR: %s failed\n", cmd);
		return REDIS_ERR;
	}
	print_reply_info(cmd, reply);
	//TODO rclock ok?

	freeReplyObject(reply);

	//TODO rclock key at src
	reply = redisCommand(src->rd, cmd);
	if (!reply) {
		printf("ERR: %s failed\n", cmd);
		return REDIS_ERR;
	}
	print_reply_info(cmd, reply);
	freeReplyObject(reply);
	//TODO rclock ok?

	//get ttl of key at src

/* Starting with Redis 2.8 the return value in case of error changed:
The command returns -2 if the key does not exist.
The command returns -1 if the key exists but has no associated expire.
*/
	snprintf(cmd, 100, "pttl %s", keyname);
	reply = redisCommand(src->rd, cmd);
	if (!reply) {
		printf("ERR: do %s failed\n", cmd);
		return REDIS_ERR;
	}
	ttl = reply->integer;
	if (ttl == -1) {
		ttl = 0;
	}

	freeReplyObject(reply);

	//get value of key at src
	snprintf(cmd, 100, "dump %s", keyname);
	reply = redisCommand(src->rd, cmd);
	if (!reply) {
		printf("ERR: do %s failed\n", cmd);
		return REDIS_ERR;
	}
	print_reply_info(cmd, reply);

	if (reply->type == REDIS_REPLY_NIL) {
		printf("WARN: get the key %s failed, may be is expired\n", keyname);
	}
	//set to dst
	if (reply->type == REDIS_REPLY_STRING) {
		setcmd = malloc(reply->len + 1024); //FIXME
		snprintf(setcmd, 100, "restore %s %lld ", keyname, ttl);
		reply_set = redisRestoreCommand (dst->rd, keyname, ttl,reply->str, reply->len);

		print_reply_info(setcmd, reply_set);
		freeReplyObject(reply_set);
	} else {
		printf("ERR: do %s failed, return not a STRING\n", cmd);
	}

	if (setcmd) free(setcmd);
	if (reply) freeReplyObject(reply);

	//TODO  set pexpire if pttl > 0

//TODO rclock key at dst
	snprintf(cmd, 100, "rcunlockkey %s", keyname);
	reply = redisCommand(dst->rd, cmd);
	if (!reply) {
		printf("ERR: %s failed\n", cmd);
		return REDIS_ERR;
	}
	print_reply_info(cmd, reply);
	freeReplyObject(reply);

	snprintf(cmd, 100, "rctransendkey %s", keyname);
	//TODO rclock key at src
	reply = redisCommand(src->rd, cmd);
	if (!reply) {
		printf("ERR: %s failed\n", cmd);
		return REDIS_ERR;
	}
	print_reply_info(cmd, reply);
	freeReplyObject(reply);

	return REDIS_OK;
}

int docmd (redisInfo *r, const char *cmd) {
	redisReply * reply;
	reply = redisCommand(r->rd, cmd);
	if (! reply ) {
	    	printf ("%s:%d exec %s failed\n", r->host, r->port, cmd);
	    	return REDIS_ERR;
	} else {
		print_reply_info_with_redisinfo(r, cmd, reply);
		freeReplyObject(reply);
	}

	return REDIS_OK;
}

void* dojob(void * ptr) {
	transInfo *t = (transInfo *) ptr;
	int status;

	while (1) {

		pthread_mutex_lock(&t->job->mutex);

		if (t->job->done || t->job->err) {
			pthread_mutex_unlock(&t->job->mutex);
			break;
		}

		t->job->seg_curr++;

		if (t->job->seg_end == t->job->seg_curr) {
			t->job->done = 1;
		}

		t->bucket = &t->job->bucketlist[t->job->seg_curr - t->job->seg_start];
		printf ("%d %d\n", t->bucket->bucket_id,t->bucket->status );
		assert(t->bucket->status == BUCKET_STATUS_TODO);

		t->bucket->status = BUCKET_STATUS_DOING;
		pthread_mutex_unlock(&t->job->mutex);

		status = transfer_bucket(t);
		if (status != REDIS_OK) {
			//TODO
		}


		pthread_mutex_lock(&t->job->mutex);
		t->bucket->status = BUCKET_STATUS_DONE;
		pthread_mutex_unlock(&t->job->mutex);

	}
	return 0;
}


int transfer_bucket(void * ptr) {
	/*
	 * 1, get the keys of src, require > 0
	 * 2, get the keys of dst , require 0
	 * 3,
	 */
	transInfo *t = (transInfo *) ptr;
	redisInfo *src, * dst;
	int bucketid;
	char cmd[1024];
	int keys_len, i,n , status;
	redisReply *keys; // store keys of bucket;


	src = &t->src;
	dst = &t->dst;
	bucketid = t->bucket->bucket_id;

	assert(   src->rd &&  dst->rd);
	assert(bucketid >=0 || bucketid < MODHASH_TOTAL_KEY );

	printf("transfer_bucket src %s:%d dst %s:%d bucket %d \n",src->host, src->port, dst->host, dst->port,  bucketid);


	status = docmd(src, "rctransserver out");
	if (status != REDIS_OK) {
		goto err;
	}

	status = docmd(dst, "rctransserver in");
	if (status != REDIS_OK) {
		goto err;
	}

	n = snprintf(cmd, 1024, "rctransbegin %d %d", bucketid, bucketid);
	status = docmd(src, cmd);
	if (status != REDIS_OK) {
		goto err;
	}
	status = docmd(dst, cmd);
	if (status != REDIS_OK) {
		goto err;
	}

	snprintf(cmd, 1024, "hashkeys %d *", bucketid);
	keys = redisCommand(src->rd, cmd);
	if (!keys) {
		//todo add a check
		goto err;
	}
	keys_len = keys->elements;
	t->bucket->key_num = keys->elements;

	for (i = 0; i < keys_len; i++) {
		status = trans_string(src, dst, keys->element[i]->str);
		if (REDIS_OK == status) {
			t->bucket->key_succ ++;
		} else {
			t->bucket->key_fail ++;
		}
	}

	freeReplyObject(keys);

    n = snprintf(cmd, 1024, "rctransend %d %d", bucketid, bucketid);
    status = docmd(src, cmd);
    if (status != REDIS_OK) {
    		goto err;
    	}
    status = docmd(dst, cmd);
    if (status != REDIS_OK) {
    		goto err;
    	}

	return REDIS_OK;

err:

	return REDIS_ERR;
}



int parse_ipport(const char* ipport, char *ip, uint32_t iplen, uint16_t * port) {
	char *p;
	int len;
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

	*port = atoi(p + 1);
	//dstDO check ip port

	return REDIS_OK;
}

int connect_redis(redisInfo * redis, char *hostname, uint16_t port) {
	struct timeval timeout = { 1, 500000 }; // 1.5 seconds
	redis->rd = redisConnectWithTimeout(hostname, port, timeout);
	if (redis->rd == NULL || redis->rd->err) {
		if (redis->rd) {
			printf("connect redis %s:%d error:%s\n", hostname, port, redis->rd->errstr);
			redisFree(redis->rd);
		} else {
			printf("connect redis %s:%d error:can't allocate redis context\n", hostname, port);
		}
		return REDIS_ERR;
	}
	printf("connect redis %s:%d succ %p\n", hostname, port, (void *)redis->rd);
	redis->port = port;
	strncpy(redis->host, hostname, sizeof(redis->host));
	return REDIS_OK;
}

int parse_proxylist(char *filename, redisInfo *proxylist) {
	int n, len, status;
	char buf[32];
	FILE *fh = fopen(filename, "r");
	if (!fh) {
		printf("open proxylist:%s failed\n", filename);
		return 0;
	}
	n = 0;
	while ((len = fread(buf, sizeof(char), 32, fh)) > 0) {
		buf[len] = '\0';
		status = parse_ipport(buf, proxylist[n].host, sizeof(proxylist[n].host), &proxylist[n].port);
		if (status == REDIS_ERR) {
			printf("parse proxylist:%s:%d failed\n", filename, n);
		}
		n++;
	}

	fclose(fh);
	return n;

}



int main(int argc, char **argv) {
	int status, n;
	char src_host[32], dst_host[32];
	uint16_t src_port, dst_port;
	int32_t seg_start, seg_end, i, idx;

	jobQueue job;
	bucketInfo * bucketlist;


	pthread_t thrd[100];
	transInfo task[100];

	char add_cmd[1024], add_buf[1024];

	int thread_num = 10;

	redisInfo proxylist[100]; //TODO use array
	int proxylist_len = 0;


	if (argc != 6) {
		printf("transfer: bad arg\n");
		printf("usage: transfer twemproxy-list  src dst seg_start seg_end\n\n");
		exit(1);
	}

	proxylist_len = parse_proxylist(argv[1], proxylist);
	if (0 == proxylist_len) {
		printf("transfer: bad twemproxy-list:%s\n", argv[1]);
		exit(1);
	}

	status = parse_ipport(argv[2], src_host, sizeof(src_host), &src_port);
	if (status == REDIS_ERR) {
		printf("transfer: bad srcip:%s", argv[2]);
		exit(1);
	}

	status = parse_ipport(argv[3], dst_host, sizeof(dst_host), &dst_port);
	if (status == REDIS_ERR) {
		printf("transfer: bad dstip:%s", argv[3]);
		exit(1);
	}

	seg_start = atoi(argv[4]);
	seg_end = atoi(argv[5]);

	if (seg_start < 0 || seg_start >= MODHASH_TOTAL_KEY) {
		printf("transfer: bad seg_start:%s", argv[4]);
		exit(1);
	}

	if (seg_end < 0 || seg_end >= MODHASH_TOTAL_KEY) {
		printf("transfer: bad seg_end:%s", argv[5]);
		exit(1);
	}

	if (seg_end < seg_start) {
		printf("transfer: require seg_start <= seg_end: %s  %s", argv[4], argv[5]);
		exit(1);
	}




	//check twemproxy login ok
	//check redis login ok
	//

	//init bucketlist
	bucketlist = malloc(sizeof(bucketInfo) * (seg_end - seg_start + 1));
	for (i=seg_start;i<=seg_end;i++) {
		idx = i-seg_start;
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
	job.err = 0;
	job.bucketlist = bucketlist;


	printf("transfer: got args %s : %d %s : %d %d %d\n", src_host, src_port, dst_host, dst_port, seg_start, seg_end);

	//init redis handle
	for (i=0;i<thread_num;i++) {
		status = connect_redis(&task[i].src, src_host, src_port);
		if (status != REDIS_OK) {
				printf("[thread %d] conn src redis %s:%d failed\n", i,src_host, src_port);
				goto end;
		}


		//docmd(&task[i].src, "PING");

		status = connect_redis(&task[i].dst, dst_host, dst_port);
		if (status != REDIS_OK) {
			printf("[thread %d] conn src redis %s:%d failed\n", i,dst_host, dst_port);
				goto end;
		}

		//docmd(&task[i].dst, "PING");

		task[i].job = &job;

	}

	//send_twemproxy_ add command
	for (i=0;i<proxylist_len;i++) {
		int sock = tcp_connect (proxylist[i].host, proxylist[i].port+1000);
		if (sock < 0) {
			printf ("add: connect to twemproxy %s:%d failed, stop transing\n", proxylist[i].host, proxylist[i].port+1000);
			goto end;
		}

		n = snprintf (add_cmd, 1024, "add alpha server pvz1 %s:%d %d-%d\n", dst_host, dst_port, seg_start, seg_end);
		printf ("cmd %s\n", add_cmd);
		n = do_proxy_cmd(sock, add_cmd, add_buf, 1024);
		printf ("return <%s>", add_buf);
		close (sock);
	}


	for (i = 0;i<thread_num;i++) {
		pthread_create(&thrd[i], NULL,  dojob, (void *) &task[i]);
	}

	for (i = 0;i<thread_num;i++) {
		pthread_join(thrd[i], NULL);
	}

	//send_twemproxy_ add command
	for (i=0;i<proxylist_len;i++) {
		int sock = tcp_connect (proxylist[i].host, proxylist[i].port+1000);
		if (sock < 0) {
			printf ("adddone: connect to twemproxy %s:%d failed, next\n", proxylist[i].host, proxylist[i].port+1000);
			continue;
		}

		n = snprintf (add_cmd, 1024, "adddone alpha server pvz1 %s:%d %d-%d\n", dst_host, dst_port, seg_start, seg_end);
		printf ("cmd %s\n", add_cmd);
		n = do_proxy_cmd(sock, add_cmd, add_buf, 1024);
		printf ("return <%s>", add_buf);
		close (sock);
	}




end:
	//TODO disconnect redis


	return 0;
}
