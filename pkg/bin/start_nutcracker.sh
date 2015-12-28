#!/bin/sh
#start a redis server
#by tencent dba @ 20130724

function usage () {
        echo "usage:"
        echo "$0 22121" 
}

PORT=$1

if [ ! -n "$PORT"  ];then
        echo "PORT not set, exit"
        usage;
        exit;
fi

shift

install_dir="/data"
soft="twemproxy-0.2.4"


rootdir="${install_dir}/$soft/$PORT/"
confpath="${rootdir}/nutcracker.$PORT.yml"
logdir="${rootdir}/log";
mkdir -p $logdir
logpath="${rootdir}/log/twemproxy.$PORT.log"
errpath="${rootdir}/log/twemproxy.$PORT.err"

if [ ! -d "$rootdir" ];then
        echo "dir $rootdir not exists"
        usage;
        exit;
fi

if [ ! -d "$logdir" ];then
        echo "dir $logdir not exists"
        usage;
        exit;
fi


if [ ! -f "$confpath" ];then
        echo "file $confpath not exists"
        usage;
        exit;
fi

stat_port=$(($PORT+1000))


cd `dirname $0`

./nutcracker  -c $confpath  -s $stat_port  -d -o $logpath >>$errpath 2>&1 &
