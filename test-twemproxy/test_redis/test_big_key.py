#!/usr/bin/env python
#coding: utf-8

from common import *
import redis

######################################################
def  big_key_test(): 
    for i in range(468-10,468-1):
      c = getconn()
      print "i = %s" % i
      kv = {}
      k=str(i)
      k += 'x' * (i - len(k))
      kv[k] = k
      c.mset(**kv)

def  big_key_test(): 
    for i in range(468-10,468-1):
      c = getconn()
      print "i = %s" % i
      kv = {}
      k=str(i)
      k += 'x' * ( - len(k) )
      v = c.mget(k)
      print "v=%s" % v

