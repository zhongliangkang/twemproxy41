#!/usr/bin/env python
#coding: utf-8

import redis

######################################################

def do_mget (c, maxlen):
    kv = {}
    k=str(maxlen)
    k += 'x' * (maxlen - len(k) )
    v = c.mget(k)
    print "v=%s" % v
    
    
def do_mset (c, maxlen):
    kv = {}
    k=str(maxlen)
    k += 'x' * (maxlen - len(k))
    kv[k] = k
   
    c.mset(**kv)

c = redis.Redis('127.0.0.1', 22121)
r = redis.Redis('127.0.0.1', 30001)
print "ping => %s" % r.ping()
 
for i in range(468-10,468-1):
    print "i = %s" % i
    do_mget(c, i)
