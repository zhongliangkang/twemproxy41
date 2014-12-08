#!/usr/bin/env python
#coding: utf-8

from common import *

def test_setget():
    r = getconn()

    rst = r.set('k', 'v')
    assert(r.get('k') == 'v')

def test_msetnx():
    r = getconn()

    #not supported
    keys = default_kv.keys()
    assert_fail('Socket closed|Connection closed', r.msetnx,**default_kv)

def test_ping_quit():
    r = getconn()
    assert(r.ping() == True)

    #get set
    rst = r.set('k', 'v')
    assert(r.get('k') == 'v')

    assert_fail('Socket closed|Connection closed', r.execute_command, 'QUIT')

def test_slow_req():
    r = getconn()

    kv = {'mkkk-%s' % i : 'mvvv-%s' % i for i in range(500000)}

    pipe = r.pipeline(transaction=False)
    pipe.set('key-1', 'v1')
    pipe.get('key-1')
    pipe.hmset('xxx', kv)
    pipe.get('key-2')
    pipe.get('key-3')
    
     
    assert_fail('timed out', pipe.execute)

def test_signal():
    #init
    nc.cleanlog()
    nc.signal('HUP')

    nc.signal('HUP')
    nc.signal('TTIN')
    nc.signal('TTOU')
    nc.signal('SEGV')

    time.sleep(.3)
#   log = file(nc.logfile()).read()

#    assert(strstr(log, 'HUP'))
 #   assert(strstr(log, 'TTIN'))
  #  assert(strstr(log, 'TTOU'))
    #assert(strstr(log, 'SEGV'))

    #recover
    nc.start()

def test_nc_stats():
    nc.stop() #reset counters
    nc.start()
    r = getconn()
    kv = {'kkk-%s' % i :'vvv-%s' % i for i in range(10)}
    for k, v in kv.items():
        r.set(k, v)
        r.get(k)

    def get_stat(name):
        time.sleep(1)
        stat = nc._info_dict()
        print(stat)
        if name in [ 'client_connections', 'client_eof', 'client_err', 'forward_error', 'fragments', 'server_ejects']:
            return stat[CLUSTER_NAME][name]

        #sum num of each server
        ret = 0
        for k, v in stat[CLUSTER_NAME].items():
            if type(v) == dict:
                ret += v[name]
        return ret

    assert(get_stat('requests') == 20)
    assert(get_stat('responses') == 20)

    ##### mget
    keys = kv.keys()
    print keys
    r.mget(keys)

    #for version<=0.3.0
    assert(get_stat('requests') == 21)
    assert(get_stat('responses') == 21)

    #for mget-improve
#    assert(get_stat('requests') == 22)
 #   assert(get_stat('responses') == 22)

def setup_and_wait():
    time.sleep(60*60)
