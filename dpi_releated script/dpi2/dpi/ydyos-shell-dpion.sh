#!/bin/bash
DPIBIN=/usr/bin
cd $DPIBIN

if [ ! -d "/var/log/dpi" ];then
   mkdir "/var/log/dpi"
fi

if [ `pwd` != $DPIBIN ]
then
echo "can't enter into $App" 
exit 0
fi

case $1 in
 stop)
 echo `date`
 oldPid=$(ps -ef|grep 'ndpiReader'|awk '{print $2}')
 echo "$Pid will be killed"
 kill -9 $oldPid
 shPid=$(ps -ef|grep 'vcmyos-shell-dpi'|awk '{print $2}')
 echo "$Pid will be killed"
 kill -9 $shPid
 ;;
 start)
  echo "PID Num= $$" 
  echo `date` 
  ./ndpiReader -i $2 -s 100 -v 1 -w ydy.txt&
  sleep 40m
  ;;
  *)
  ;;
esac




