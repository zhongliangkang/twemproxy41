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


#check if this server is docker?!
#docker server mount the disk to /data1, but /data is int the / without mount to any dev

dfinfo=`df -h`
idata1=`echo "$dfinfo"|grep -w  "/data1"|wc -l`
idata=`echo "$dfinfo"|grep -w "/data"|wc -l`
idataredis=` ls -ld /data/redis/ 2>/dev/null|wc -l`
idata1redis=`ls -ld /data1/redis/ 2>/dev/null|wc -l`

if [ $idata -eq 1 ]
then
        echo "data dis found, use it";
elif [ $idata -eq 0 -a $idata1 -eq 1 -a $idataredis -eq 0 ]
then
        echo "new docker found, no redis installed"
        mkdir -p /data1/$soft
        mkdir -p /data
        ln -s /data1/$soft /data/$soft

        #process dbbak dir
        if [ -d /data/dbbak ]
        then
                mv /data/dbbak/ /data/dbbak.bak
        fi
        mkdir -p /data1/dbbak/
        ln -s /data1/dbbak /data/dbbak;

        #chown
        chown -R mysql /data1/dbbak  /data1/redis
fi


rootdir="${install_dir}/$soft/$PORT/"
logdir="$install_dir/log/"
confpath="${rootdir}/nutcracker.$PORT.yml"

mylocalip=`/sbin/ifconfig |  grep -A1 "eth" | grep "inet addr:" | awk -F: '{ print $2 }' | grep -E "^10\.|^192\.|^172\." | awk '{ print $1 }'|head -n 1`

#for support 100.64/10 network special
mylocal100=`/sbin/ifconfig |  grep -A1 "eth" | grep "inet addr:" | awk -F: '{ print $2 }' | grep -E "^100\." | awk '{ print $1 }'|head -n 1`

if [  -d "$rootdir" ];then
        echo "error: dir $rootdir already exists, exit!"
        exit;
fi

mkdir -p $rootdir
if [ "$mylocalip" != "" ]
then
    sed -e "s/\$PORT/$PORT/g" ../conf/nutcracker.yml |sed -e "s/\$REDIS/$REDIS/g" |sed -e "s/0.0.0.0/$mylocalip/g" > $confpath
else
    sed -e "s/\$PORT/$PORT/g" ../conf/nutcracker.yml |sed -e "s/\$REDIS/$REDIS/g" |sed -e "s/0.0.0.0/$mylocal100/g" > $confpath
fi

if [ "$TPASS" != "1" ]
then
   sed -i "s/#password:/password: $TPASS/g"  $confpath
fi

if [ "$RPASS" != "1" ]
then
   sed -i "s/#redis_password:/redis_password: $RPASS/g"  $confpath
fi
