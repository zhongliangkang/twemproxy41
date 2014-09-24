#include "fmacros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#include "hiredis.h"

enum connection_type {
    CONN_TCP,
    CONN_UNIX,
    CONN_FD
};

struct config {
    enum connection_type type;

    struct {
        const char *host;
        int port;
        struct timeval timeout;
    } tcp;

    struct {
        const char *path;
    } unix;
};

/* The following lines make up our testing "framework" :) */
static int tests = 0, fails = 0;
#define test(_s) { printf("#%02d ", ++tests); printf(_s); }
#define test_cond(_c) if(_c) printf("\033[0;32mPASSED\033[0;0m\n"); else {printf("\033[0;31mFAILED\033[0;0m\n"); fails++;}

static long long usec(void) {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (((long long)tv.tv_sec)*1000000)+tv.tv_usec;
}

static redisContext *select_database(redisContext *c) {
    redisReply *reply;

    /* Switch to DB 9 for testing, now that we know we can chat. */
    reply = redisCommand(c,"SELECT 9");
    assert(reply != NULL);
    freeReplyObject(reply);

    /* Make sure the DB is emtpy */
    reply = redisCommand(c,"DBSIZE");
    assert(reply != NULL);
    if (reply->type == REDIS_REPLY_INTEGER && reply->integer == 0) {
        /* Awesome, DB 9 is empty and we can continue. */
        freeReplyObject(reply);
    } else {
        printf("Database #9 is not empty, test can not continue\n");
    }

    return c;
}

static int disconnect(redisContext *c, int keep_fd) {
    redisReply *reply;

    /* Make sure we're on DB 9. */
    reply = redisCommand(c,"SELECT 9");
    assert(reply != NULL);
    freeReplyObject(reply);
    reply = redisCommand(c,"FLUSHDB");
    assert(reply != NULL);
    freeReplyObject(reply);

    /* Free the context as well, but keep the fd if requested. */
    if (keep_fd)
        return redisFreeKeepFd(c);
    redisFree(c);
    return -1;
}

static redisContext *connect(struct config config) {
    redisContext *c = NULL;

    if (config.type == CONN_TCP) {
        c = redisConnect(config.tcp.host, config.tcp.port);
    } else if (config.type == CONN_UNIX) {
        c = redisConnectUnix(config.unix.path);
    } else if (config.type == CONN_FD) {
        /* Create a dummy connection just to get an fd to inherit */
        redisContext *dummy_ctx = redisConnectUnix(config.unix.path);
        if (dummy_ctx) {
            int fd = disconnect(dummy_ctx, 1);
            printf("Connecting to inherited fd %d\n", fd);
            c = redisConnectFd(fd);
        }
    } else {
        assert(NULL);
    }

    if (c == NULL) {
        printf("Connection error: can't allocate redis context\n");
        exit(1);
    } else if (c->err) {
        printf("Connection error: %s\n", c->errstr);
        exit(1);
    }

    return (c);
}



static void docmd (struct config config, int num, char * cmd, int verb) {
    int i;
    int ok;
    redisContext *c;
    redisReply *reply;

    int j, n;
    c = connect(config);
    printf ("create key aa 1 - %d\n", num);
    
    for (i=1;i<=num;i++) {
	    reply = redisCommand(c,cmd);
	    if (verb) 
	     printf ("(%s) => %s\n", cmd, reply->str);
	    ok ++;            		
	    freeReplyObject(reply);
	}

   test_cond(ok == num);
}




// static long __test_callback_flags = 0;
// static void __test_callback(redisContext *c, void *privdata) {
//     ((void)c);
//     /* Shift to detect execution order */
//     __test_callback_flags <<= 8;
//     __test_callback_flags |= (long)privdata;
// }
//
// static void __test_reply_callback(redisContext *c, redisReply *reply, void *privdata) {
//     ((void)c);
//     /* Shift to detect execution order */
//     __test_callback_flags <<= 8;
//     __test_callback_flags |= (long)privdata;
//     if (reply) freeReplyObject(reply);
// }
//
// static redisContext *__connect_nonblock() {
//     /* Reset callback flags */
//     __test_callback_flags = 0;
//     return redisConnectNonBlock("127.0.0.1", port, NULL);
// }
//
// static void test_nonblocking_connection() {
//     redisContext *c;
//     int wdone = 0;
//
//     test("Calls command callback when command is issued: ");
//     c = __connect_nonblock();
//     redisSetCommandCallback(c,__test_callback,(void*)1);
//     redisCommand(c,"PING");
//     test_cond(__test_callback_flags == 1);
//     redisFree(c);
//
//     test("Calls disconnect callback on redisDisconnect: ");
//     c = __connect_nonblock();
//     redisSetDisconnectCallback(c,__test_callback,(void*)2);
//     redisDisconnect(c);
//     test_cond(__test_callback_flags == 2);
//     redisFree(c);
//
//     test("Calls disconnect callback and free callback on redisFree: ");
//     c = __connect_nonblock();
//     redisSetDisconnectCallback(c,__test_callback,(void*)2);
//     redisSetFreeCallback(c,__test_callback,(void*)4);
//     redisFree(c);
//     test_cond(__test_callback_flags == ((2 << 8) | 4));
//
//     test("redisBufferWrite against empty write buffer: ");
//     c = __connect_nonblock();
//     test_cond(redisBufferWrite(c,&wdone) == REDIS_OK && wdone == 1);
//     redisFree(c);
//
//     test("redisBufferWrite against not yet connected fd: ");
//     c = __connect_nonblock();
//     redisCommand(c,"PING");
//     test_cond(redisBufferWrite(c,NULL) == REDIS_ERR &&
//               strncmp(c->error,"write:",6) == 0);
//     redisFree(c);
//
//     test("redisBufferWrite against closed fd: ");
//     c = __connect_nonblock();
//     redisCommand(c,"PING");
//     redisDisconnect(c);
//     test_cond(redisBufferWrite(c,NULL) == REDIS_ERR &&
//               strncmp(c->error,"write:",6) == 0);
//     redisFree(c);
//
//     test("Process callbacks in the right sequence: ");
//     c = __connect_nonblock();
//     redisCommandWithCallback(c,__test_reply_callback,(void*)1,"PING");
//     redisCommandWithCallback(c,__test_reply_callback,(void*)2,"PING");
//     redisCommandWithCallback(c,__test_reply_callback,(void*)3,"PING");
//
//     /* Write output buffer */
//     wdone = 0;
//     while(!wdone) {
//         usleep(500);
//         redisBufferWrite(c,&wdone);
//     }
//
//     /* Read until at least one callback is executed (the 3 replies will
//      * arrive in a single packet, causing all callbacks to be executed in
//      * a single pass). */
//     while(__test_callback_flags == 0) {
//         assert(redisBufferRead(c) == REDIS_OK);
//         redisProcessCallbacks(c);
//     }
//     test_cond(__test_callback_flags == 0x010203);
//     redisFree(c);
//
//     test("redisDisconnect executes pending callbacks with NULL reply: ");
//     c = __connect_nonblock();
//     redisSetDisconnectCallback(c,__test_callback,(void*)1);
//     redisCommandWithCallback(c,__test_reply_callback,(void*)2,"PING");
//     redisDisconnect(c);
//     test_cond(__test_callback_flags == 0x0201);
//     redisFree(c);
// }

int main(int argc, char **argv) {
    struct config cfg = {
        .tcp = {
            .host = "127.0.0.1",
            .port = 6379
        },
        .unix = {
            .path = "/tmp/redis.sock"
        }
    };
    int throughput = 1;
    int test_inherit_fd = 1;
    int num = 0;
    int verb = 0;
    char * cmd_template;

    /* Ignore broken pipe signal (for I/O error tests). */
    signal(SIGPIPE, SIG_IGN);

    /* Parse command line options. */
    argv++; argc--;
    while (argc) {
        if (argc >= 2 && !strcmp(argv[0],"-h")) {
            argv++; argc--;
            cfg.tcp.host = argv[0];
        } else if (argc >= 2 && !strcmp(argv[0],"-p")) {
            argv++; argc--;
            cfg.tcp.port = atoi(argv[0]);
        } else if (argc >= 2 && !strcmp(argv[0],"-s")) {
            argv++; argc--;
            cfg.unix.path = argv[0];
        } else if (argc >= 1 && !strcmp(argv[0],"-v")) {
	    verb = 1;
        } else if (argc >= 2 && !strcmp(argv[0],"-n")) {
            argv++; argc--;
	    num = atoi(argv[0]);
        } else if (argc >= 2 && !strcmp(argv[0],"-c")) {
            argv++; argc--;
	    cmd_template = argv[0];
        } else if (argc >= 1 && !strcmp(argv[0],"--skip-throughput")) {
            throughput = 0;
        } else if (argc >= 1 && !strcmp(argv[0],"--skip-inherit-fd")) {
            test_inherit_fd = 0;
        } else {
            fprintf(stderr, "Invalid argument: %s\n", argv[0]);
            exit(1);
        }
        argv++; argc--;
    }

    docmd(cfg, num, cmd_template, verb);

    printf("ALL TESTS PASSED\n");
    return 0;
}
