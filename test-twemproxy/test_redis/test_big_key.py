#!/usr/bin/env python
#coding: utf-8

from common import *
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

def  big_key_test(): 
    for i in range(468-10,468-1):
      c = getconn()
      print "i = %s" % i
      do_mget(c, i)
