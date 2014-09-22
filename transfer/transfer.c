#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>
#include <assert.h>
#include <transfer.h>


/*
 *
 */

char redis_reply_name[][8] = { "", "STRING", "ARRAY", "INTEGER", "NIL", "STATUS", "ERROR" };

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
//	assert(reply->type <= REDIS_REPLY_ERROR );
	printf("cmd:'%s'\t return len: %d type:%d %s str:%s elem:%zd\n", cmd, reply->len, reply->type,
			redis_reply_name[reply->type], reply->str, reply->elements);

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

int intlen(int start) {

    int end = 1;

    while(start >= 10) {
        start = start/10;
        end++;
    }

    return end;
}

/*
 * trans_string
 *
 */
int trans_string(redisInfo *src, redisInfo *dst, char * keyname) {
	redisReply    *reply_set, *reply;
	char cmd[100];
	char * setcmd = NULL;
	long long setcmd_len = 1024;
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
	//	setcmd = malloc(reply->len + 1024); //FIXME
	//	int n = snprintf(setcmd, 100, "restore %s %d ", keyname, ttl);
	//	memcpy(setcmd + n , reply->str, reply->len);
		//reply_set = redisCommand(dst->rd, setcmd);
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
	freeReplyObject(reply);

	//TODO rclock key at src
	reply = redisCommand(src->rd, cmd);
	if (!reply) {
		printf("ERR: %s failed\n", cmd);
		return REDIS_ERR;
	}
	freeReplyObject(reply);

	return REDIS_OK;
}

int transfer_bucket(redisInfo * src, redisInfo * dst, int bucketid) {
	/*
	 * 1, get the keys of src, require > 0
	 * 2, get the keys of dst , require 0
	 * 3,
	 */
	char cmd[1024];
	int keys_len, i,n , status;
	redisReply *keys; // store keys of bucket;
	redisReply *type_reply ; //store type of transing key;


	char keytype_name[REDIS_KEYTYPE_LEN];
	uint32_t keytype;
	snprintf(cmd, 1024, "keys *");
	keys = redisCommand(src->rd, cmd);
	keys_len = keys->elements;
//	print_reply_info (cmd, keys);

	printf("src %s:%d dst %s:%d bucket %d keyslen: %d\n",src->host, src->port, dst->host, dst->port,  bucketid, keys_len);

	for (i = 0; i < keys_len; i++) {
		status = trans_string(src, dst, keys->element[i]->str);
	}

	freeReplyObject(keys);

	return REDIS_OK;
/*

		n = snprintf(cmd, 1024, "type %s", keys->element[i]->str);
		type_reply = redisCommand(src->rd, cmd);
		print_reply_info(cmd, type_reply);


		switch (type_reply->len) {
		case 3:
			if (0 == strncmp(keytype_name, "set", REDIS_KEYTYPE_LEN)) {
				keytype = REDIS_KEYTYPE_SET;
			}
			break;
		case 4:
			if (0 == strncmp(keytype_name, "list", REDIS_KEYTYPE_LEN)) {
				keytype = REDIS_KEYTYPE_LIST;
			} else if (0 == strncmp(keytype_name, "hash", REDIS_KEYTYPE_LEN)) {
				keytype = REDIS_KEYTYPE_HASH;
			} else if (0 == strncmp(keytype_name, "zset", REDIS_KEYTYPE_LEN)) {
				keytype = REDIS_KEYTYPE_ZSET;
			} else if (0 == strncmp(keytype_name, "none", REDIS_KEYTYPE_LEN)) {
				keytype = REDIS_KEYTYPE_NONE;
			} else {
				keytype = REDIS_KEYTYPE_UNKNOWN;
			}
			break;

		case 5:
			if (0 == strncmp(keytype_name, "string", REDIS_KEYTYPE_LEN)) {
				keytype = REDIS_KEYTYPE_STRING;
			} else {
				keytype = REDIS_KEYTYPE_UNKNOWN;
			}
			break;

		default:
			keytype = REDIS_KEYTYPE_UNKNOWN;

		}
		freeReplyObject(type_reply);

		if (keytype == REDIS_KEYTYPE_NONE) {
			printf ("WARN ");
		}


	} */



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
	printf("connect redis %s:%d succ %p\n", hostname, port, redis->rd);
	redis->port = port;
	strncpy(redis->host, hostname, sizeof(redis->host));
	return REDIS_OK;
}

int main(int argc, char **argv) {
	int status;
	char src_host[32], dst_host[32];
	uint16_t src_port, dst_port;
	int seg_start;
	int seg_end;

	struct redis_info src;
	struct redis_info dst;
//	redisContext *src;
//	redisContext *dst;

//	log_init(11, NULL);//out put to stderr



	redisReply *reply;

	if (argc != 5) {
		printf  ("usage: transfer src dst seg_start seg_end");
		exit(1);
	}

	status = parse_ipport(argv[1], src_host, sizeof(src_host), &src_port);
	if (status == REDIS_ERR) {
		printf("bad srcip:%s", argv[1]);
		exit(1);
	}

	status = parse_ipport(argv[2], dst_host, sizeof(dst_host), &dst_port);
	if (status == REDIS_ERR) {
		printf("bad dstip:%s", argv[2]);
		exit(1);
	}

	seg_start = atoi(argv[3]);
	seg_end = atoi(argv[4]);

	//dstDO  check 0 <= start < end <
	//dstDO check src != dst

	printf("got args %s : %d %s : %d %d %d\n", src_host, src_port, dst_host, dst_port, seg_start, seg_end);
	status = connect_redis(&src, src_host, src_port);

	if (status != REDIS_OK) {
			printf("conn src redis failed\n");
			goto end;
	}

	status = connect_redis(&dst, dst_host, dst_port);
	if (status != REDIS_OK) {
		printf("conn dst redis failed\n");
		goto end;
	}

	reply = redisCommand(src.rd, "PING");
	printf("PING: %s\n", reply->str);
	freeReplyObject(reply);

	transfer_bucket(&src, &dst, seg_start);

end:
	if (src.rd)
		redisFree(src.rd);
	if (dst.rd)
		redisFree(dst.rd);

	return 0;
}
