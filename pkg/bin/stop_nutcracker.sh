#!/bin/sh
#start a redis server
#by tencent dba @ 20130724

function usage () {
        echo "usage:"
        echo "$0 3689" 
        echo "$0 3689 + some redis arg like: $0 3689 --slaveof 1.1.1.1 3679" 
}

PORT=$1

if [ ! -n "$PORT"  ];then
        echo "PORT not set, exit"
        usage;
        exit;
fi

shift

pid=`ps -efwww|grep -w nutcracker|grep "nutcracker.$PORT.yml"|grep -v grep |awk '{print $2}'`

echo "pid:$pid ."

if [ $pid  != "" ]
then
	echo "stop nutcracker on port:$PORT ..."
	kill $pid
	echo "stop nutcracker done."
else
	echo "not nutcracker running on port: $PORT"
fi
