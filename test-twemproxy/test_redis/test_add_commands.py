#!/usr/bin/env python
#coding: utf-8

from common import *

def test_nc_ping ():
   r = getconn()
   assert(r.ping() )


def test_nc_auth ():
   r = getconn()
   cmd = "redis-cli -h %s -p %s auth badpass" % (nc.host(), nc.port())
   ret= system(cmd)
   assert (ret, "RR Client sent AUTH, but no password is set")
