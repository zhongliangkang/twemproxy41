/*
 * Copyright (c) 2009-2011, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2010-2011, Pieter Noordhuis <pcnoordhuis at gmail dot com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TRANSFER_H
#define __TRANSFER_H
#include <stdio.h> /* for size_t */
#include <stdarg.h> /* for va_list */
#include <sys/time.h> /* for struct timeval */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <hiredis.h>
#include <stdbool.h>
#include <pthread.h>

#define BUCKET_STATUS_TODO  1
#define BUCKET_STATUS_DOING 2
#define BUCKET_STATUS_DONE  3


#define MODHASH_TOTAL_KEY 420000
#define REDIS_KEYTYPE_LEN 32

#define REDIS_KEYTYPE_STRING 1
#define REDIS_KEYTYPE_LIST 2
#define REDIS_KEYTYPE_HASH 3
#define REDIS_KEYTYPE_SET 4
#define REDIS_KEYTYPE_ZSET 5
#define REDIS_KEYTYPE_NONE 999
#define REDIS_KEYTYPE_UNKNOWN 999


#define REDIS_DUP 2

typedef struct twemproxy_info {
	char host[16];
	uint16_t port;
	uint16_t stat_port; // twemproxy has a stat_port;
	int fd; //conn fd;
} proxyInfo;


typedef struct redis_info {
	char host[16];
	uint16_t port;
	uint16_t stat_port; // twemproxy has a stat_port;
	redisContext * rd; //redis descriptor
} redisInfo;

typedef struct bucket_info {
	int bucket_id;
	int status ; //0 todo, 1:doing ; 2:done
	int key_num ;
	int key_succ;
	int key_fail;
} bucketInfo ;



typedef struct job_queue {
//	redisInfo src;
//	redisInfo dst;
	int err;
	int done;
	bucketInfo * bucketlist;
	redisReply * keys;

	uint32_t key_fail;
	uint32_t key_fail_enable;
	pthread_mutex_t mutex;
} jobQueue;

typedef struct trans_info {
	redisInfo src;
	redisInfo dst;
	jobQueue * job;
	bucketInfo * bucket;
	uint32_t processid ;
	pthread_mutex_t mutex;
} transInfo;




int parse_ipport(const char* ipport, char *ip, uint32_t iplen, uint16_t * port) ;
int transfer_bucket(void *ptr);
int connect_redis(redisInfo * redis, char *hostname, uint16_t port, char* pass);
int trans_string(redisInfo *src, redisInfo *dst, char * keyname, int keyname_len) ;
int check_reply_ok(redisReply * reply);
int check_reply_status_str(redisReply * reply, const char * str);
void check_reply_and_free(redisReply * reply);
int check_reply_ok_and_free(redisInfo *ri,const char * cmd, redisReply * reply);

void print_reply_info(char *cmd, redisReply * reply);


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
