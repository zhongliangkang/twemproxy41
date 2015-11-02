#!/usr/bin/env python
#coding: utf-8

from common import *

def get_conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((nc.host(), nc.port()))
    s.settimeout(.3)
    return s

def test_nc_increx():
    r = get_conn()
    r1 = getconn();
    r1.delete("kkkkk");
    req="*3\r\n$6\r\nincrex\r\n$5\r\nkkkkk\r\n$3\r\n100\r\n"
    rsp=":1\r\n"

    r.sendall("*3\r\n$6\r\nincrex\r\n$5\r\nkkkkk\r\n$3\r\n100\r\n")
    data = r.recv(10000);
    assert(data == rsp)

    rsp=":2\r\n"
    r.sendall("*3\r\n$6\r\nincrex\r\n$5\r\nkkkkk\r\n$3\r\n100\r\n")
    data = r.recv(10000);
    assert(data == rsp)


    time.sleep(1.99);
    rsp=":98\r\n"
    r.sendall("*2\r\n$3\r\nttl\r\n$5\r\nkkkkk\r\n")
    data = r.recv(10000);
    print data
    assert(data == rsp)

def test_hmgetall():
    r = get_conn()
    r1 = getconn();
    r1.hset('h1','k1','v1');
    r1.hset('h2','k2','v2');
    r1.hset('h3','k3','v3');

    r.sendall("*4\r\n$8\r\nhmgetall\r\n$2\r\nh1\r\n$2\r\nh2\r\n$3\r\nh3\r\n");
    hmgetall=r.recv(1000);

