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

#ifndef _NC_LOG_H_
#define _NC_LOG_H_

struct logger {
    char *name;  /* log file name */
    int  level;  /* log level */
    int  fd;     /* log file descriptor */
    int  nerror; /* # log error */
};

#define LOG_EMERG   0   /* system in unusable */
#define LOG_ALERT   1   /* action must be taken immediately */
#define LOG_CRIT    2   /* critical conditions */
#define LOG_ERR     3   /* error conditions */
#define LOG_WARN    4   /* warning conditions */
#define LOG_NOTICE  5   /* normal but significant condition (default) */
#define LOG_INFO    6   /* informational */
#define LOG_DEBUG   7   /* debug messages */
#define LOG_VERB    8   /* verbose messages */
#define LOG_VVERB   9   /* verbose messages on crack */
#define LOG_VVVERB  10  /* verbose messages on ganga */
#define LOG_PVERB   11  /* periodic verbose messages on crack */

#define LOG_MAX_LEN 256 /* max length of log message */

/*
 * log_stderr   - log to stderr
 * loga         - log always
 * loga_hexdump - log hexdump always
 * log_error    - error log messages
 * log_warn     - warning log messages
 * log_panic    - log messages followed by a panic
 * ...
 * log_debug    - debug log messages based on a log level
 * log_hexdump  - hexadump -C of a log buffer
 */
#ifdef NC_DEBUG_LOG

#define log_debug(_level, ...) do {                                         \
    if (log_loggable(_level) != 0) {                                        \
        _log(__FILE__, __LINE__, 0, __VA_ARGS__);                           \
    }                                                                       \
} while (0)

#define log_hexdump(_level, _data, _datalen, ...) do {                      \
    if (log_loggable(_level) != 0) {                                        \
        _log(__FILE__, __LINE__, 0, __VA_ARGS__);                           \
        _log_hexdump(__FILE__, __LINE__, (char *)(_data), (int)(_datalen),  \
                     __VA_ARGS__);                                          \
    }                                                                       \
} while (0)

#else

#define log_debug(_level, ...)
#define log_hexdump(_level, _data, _datalen, ...)

#endif

#define log_stderr(...) do {                                                \
    _log_stderr(__VA_ARGS__);                                               \
} while (0)

#define loga(...) do {                                                      \
    _log(__FILE__, __LINE__, 0, __VA_ARGS__);                               \
} while (0)

#define loga_hexdump(_data, _datalen, ...) do {                             \
    _log(__FILE__, __LINE__, 0, __VA_ARGS__);                               \
    _log_hexdump(__FILE__, __LINE__, (char *)(_data), (int)(_datalen),      \
                 __VA_ARGS__);                                              \
} while (0)                                                                 \

#define log_error(...) do {                                                 \
    if (log_loggable(LOG_ALERT) != 0) {                                     \
        _log(__FILE__, __LINE__, 0, __VA_ARGS__);                           \
    }                                                                       \
} while (0)

#define log_warn(...) do {                                                  \
    if (log_loggable(LOG_WARN) != 0) {                                      \
        _log(__FILE__, __LINE__, 0, __VA_ARGS__);                           \
    }                                                                       \
} while (0)

#define log_panic(...) do {                                                 \
    if (log_loggable(LOG_EMERG) != 0) {                                     \
        _log(__FILE__, __LINE__, 1, __VA_ARGS__);                           \
    }                                                                       \
} while (0)

int log_init(int level, char *filename);
void log_deinit(void);
void log_level_up(void);
void log_level_down(void);
void log_level_set(int level);
void log_reopen(void);
int log_loggable(int level);
void _log(const char *file, int line, int panic, const char *fmt, ...);
void _log_stderr(const char *fmt, ...);
void _log_hexdump(const char *file, int line, char *data, int datalen, const char *fmt, ...);


#endif


/* from NC_UTIL.h */
#ifndef _NC_UTIL_H_
#define _NC_UTIL_H_
#define LF                  (uint8_t) 10
#define CR                  (uint8_t) 13
#define CRLF                "\x0d\x0a"
#define CRLF_LEN            (sizeof("\x0d\x0a") - 1)

#define NELEMS(a)           ((sizeof(a)) / sizeof((a)[0]))

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))

#define SQUARE(d)           ((d) * (d))
#define VAR(s, s2, n)       (((n) < 2) ? 0.0 : ((s2) - SQUARE(s)/(n)) / ((n) - 1))
#define STDDEV(s, s2, n)    (((n) < 2) ? 0.0 : sqrt(VAR((s), (s2), (n))))

#define NC_INET4_ADDRSTRLEN (sizeof("255.255.255.255") - 1)
#define NC_INET6_ADDRSTRLEN \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define NC_INET_ADDRSTRLEN  MAX(NC_INET4_ADDRSTRLEN, NC_INET6_ADDRSTRLEN)
#define NC_UNIX_ADDRSTRLEN  \
    (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#define NC_MAXHOSTNAMELEN   256

/*
 * Length of 1 byte, 2 bytes, 4 bytes, 8 bytes and largest integral
 * type (uintmax_t) in ascii, including the null terminator '\0'
 *
 * From stdint.h, we have:
 * # define UINT8_MAX	(255)
 * # define UINT16_MAX	(65535)
 * # define UINT32_MAX	(4294967295U)
 * # define UINT64_MAX	(__UINT64_C(18446744073709551615))
 */
#define NC_UINT8_MAXLEN     (3 + 1)
#define NC_UINT16_MAXLEN    (5 + 1)
#define NC_UINT32_MAXLEN    (10 + 1)
#define NC_UINT64_MAXLEN    (20 + 1)
#define NC_UINTMAX_MAXLEN   NC_UINT64_MAXLEN

/*
 * Make data 'd' or pointer 'p', n-byte aligned, where n is a power of 2
 * of 2.
 */
#define NC_ALIGNMENT        sizeof(unsigned long) /* platform word */
#define NC_ALIGN(d, n)      (((d) + (n - 1)) & ~(n - 1))
#define NC_ALIGN_PTR(p, n)  \
    (void *) (((uintptr_t) (p) + ((uintptr_t) n - 1)) & ~((uintptr_t) n - 1))
#endif
