#!/bin/bash
DPIBIN=/opt/vyatta/sbin
cd $DPIBIN

if [ `pwd` != $App ]
then
echo "can't enter into $App" 
exit 0
fi
echo $1
echo $2
while :
do
 case $1 in
 stop)
 echo `date`
 oldPid=$(ps -ef|grep 'ndpiReader'|awk '{print $2}')
 echo "$Pid will be killed"
 kill -9 $oldPid
 shPid=$(ps -ef|grep 'vcmyos-shell-dpi'|awk '{print $2}')
 echo "$Pid will be killed"
 kill -9 $shPid
 break
 ;;
 start)
  echo "#########################" 
  echo "PID Num= $$" 
  echo `date` 
  ./ndpiReader -i $2 -s 30 -v 1 -w ydy.txt&
  sleep 30s
  continue
  ;;
  *)
  ;;
  esac
done




