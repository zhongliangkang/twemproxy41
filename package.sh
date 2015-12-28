#!/bin/sh

dir=`dirname $0`
cd $dir

./compile.sh

if [ $? -eq 0 ]
then
  echo "compile ok"
else
  echo "compile failed, exit!"
  exit 1
fi

version="twemproxy-0.4.1-v4"
mkdir -p $version
cp -frp  pkg/*  $version

cp -frp src/nutcracker $version/bin/

tree $version


if [ -f $version.tar.gz ]
then
   rm $version.tar.gz
fi

tar -zcvf $version.tar.gz $version
