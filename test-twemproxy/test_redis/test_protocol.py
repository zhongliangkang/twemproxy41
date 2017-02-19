#!/usr/bin/env python
from common import *

def get_conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((nc.host(), nc.port()))
    s.settimeout(.3)
    return s

def _test(req, resp, sleep=0):
    s = get_conn()

    for i in req:
        s.sendall(i)
        time.sleep(sleep)

    s.settimeout(.3)

    data = s.recv(10000)
    assert(data == resp)

def test_slow():
    req = '*1\r\n$4\r\nPING\r\n'
    resp = '+PONG\r\n'

    if large > 1000:
        sleep = 1
    else:
        sleep = .1

    _test(req, resp, sleep)

def test_pingpong():
    req = '*1\r\n$4\r\nPING\r\n'
    resp = '+PONG\r\n'
    _test(req, resp)

def _test_bad(req):
    s = get_conn()

    s.sendall(req)
    data = s.recv(10000)
    print req
    print data

    #all bad command are return with -ERR unkown command since 2017.2.19
    #assert('' == s.recv(1000))  # peer is closed
    assert(data.startswith('-ERR unkown command'))

def test_badreq():
    reqs = [
        '*1\r\n$3\r\nPING\r\n',
        '\r\n',
        '$2\r\n$4\r\nkeys\r\n$1\r\n*\r\n',
        '*2\r\n$4\r\nkeys\r\n$1\r\n*\r\n',
        '*3abcdefg\r\n',
        '*3\r\n*abcde\r\n',
        '*4\r\n$4\r\nMSET\r\n$1\r\nA\r\n$1\r\nA\r\n$1\r\nA\r\n',
        '*3\r\n$abcde\r\n',
        '*3\r\n$3abcde\r\n',
        '*3\r\n$3\r\nabcde\r\n'
    ]

    for req in reqs:
        _test_bad(req)


def test_wrong_argc():
    s = get_conn()

    s.sendall('*1\r\n$3\r\nGET\r\n')
    #assert_fail('timed out', s.recv, 10000)
 
    data = s.recv(1000);
    #assert('' == s.recv(1000))  # peer is closed
    assert(data.startswith('-ERR unkown command'))

    s.sendall('*3\r\n$3\r\nGET\r\n$5\r\nkkkkk\r\n$5\r\nvvvvv\r\n')
    data = s.recv(10000)
    print data
    assert(data.startswith('-ERR unkown command'))

    s.sendall('3\r$3\r\nGET\r\n$5\r\nkkkkk\r\n$5\r\nvvvvv\r\n')
    data = s.recv(10000)
    print data
    assert(data.startswith('-ERR unkown command'))

def test_protcal_err():
    s = get_conn();
    #invalid protocal, return a ERR package,and twemproxy close the connection
    s.sendall('testprotocalerr\r\n')
    data = s.recv(1000);
    assert(data == '-ERR unkown command or protocal error\r\n')
    assert('' == s.recv(100))  # peer is closed

    s = get_conn();
    #invalid protocal, return a ERR package,and twemproxy close the connection
    s.sendall('3\r\n$3\r\nxxxx\r\n')
    data = s.recv(1000);
    print data
    assert(data == '-ERR unkown command or protocal error\r\n')
    assert('' == s.recv(100))  # peer is closed
