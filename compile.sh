#!/bin/sh
#
# for compile twemproxy
#
############################

#autoreconf -fvi
CFLAGS="-g -O3 -fno-strict-aliasing" ./configure --enable-debug=log
make
