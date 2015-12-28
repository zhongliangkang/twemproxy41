#!/bin/sh
#start a redis server
#by tencent dba @ 20130724

function usage () {
        echo "usage:"
        echo "$0  PORT  IS_REDIS_BOOL TWEMPASS REDIS_PASS  (if no password, use 1 instead)"
        echo "$0  22121 <true|false> <TWEMPASS> <REDIS_PASS>" 
}

PORT=$1
REDIS=$2
TPASS="$3"
RPASS="$4"

if [ $# -lt 4 ]
then
    usage;
    exit
fi

if [ ! -n "$PORT"  ];then
        echo "error: PORT not set, exit"
        usage;
        exit;
fi

if [ "$REDIS" != "true" -a "$REDIS" != "false" ]
then
    echo "error: invalid config: $REDIS , must be 'true' or 'false'"
    usage; 
    exit;
fi


shift

install_dir="/data"
soft="twemproxy-0.2.4"


rootdir="${install_dir}/$soft/$PORT/"
logdir="$install_dir/log/"
confpath="${rootdir}/nutcracker.$PORT.yml"

mylocalip=`/sbin/ifconfig |  grep -A1 "eth" | grep "inet addr:" | awk -F: '{ print $2 }' | grep -E "^10|^192|^172" | awk '{ print $1 }'|head -n 1`

if [  -d "$rootdir" ];then
        echo "error: dir $rootdir already exists, exit!"
        exit;
fi

mkdir -p $rootdir

sed -e "s/\$PORT/$PORT/g" ../conf/nutcracker.yml |sed -e "s/\$REDIS/$REDIS/g" |sed -e "s/0.0.0.0/$mylocalip/g" > $confpath

if [ "$TPASS" != "1" ]
then
   sed -i "s/#password:/password: $TPASS/g"  $confpath
fi

if [ "$RPASS" != "1" ]
then
   sed -i "s/#redis_password:/redis_password: $RPASS/g"  $confpath
fi
