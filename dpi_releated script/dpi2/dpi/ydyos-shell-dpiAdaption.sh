#!/bin/bash
DPILog=/var/log/dpi/
ADP=adaption
lanNW=$2
nextHop=$3
numcnt=$4


cd $DPILog
if [ ! -d "adaption" ]
then
   mkdir $ADP
fi


checkfile=$1.txt
if [ ! -f $checkfile ];then
  echo "$checkfile not exitst"
  exit 1
fi


cd $DPILog/adaption

if [ $numcnt -eq 0 ];then
       rm $1*
fi

addpre=_add.txt
delpre=_del.txt
tmpfile=tmp.txt
tmp2file=tmp2.txt
flag=0;
destIP=""
if [ ! -f $checkfile ];then
  cp ../$checkfile ./
  cnt=0;
  #rm $1$addpre
  #rm $1$delpre
  echo "" > $1$addpre
  echo "" > $1$delpre
  while read -r line
  do
   flag=0;
   fstr=`echo $line | cut -d \  -f 1`
   sstr=`echo $line | cut -d \  -f 2`
   if [[ $fstr =~ $2 ]];then
       flag=1
       if [[ $sstr =~ $2 ]];then
       flag=2
	   fi
	   if [[ $sstr =~ $3 ]];then
       flag=2
	   fi
   fi
   if [[ $fstr =~ $3 ]];then
       flag=1
       if [[ $sstr =~ $2 ]];then
       flag=2
	   fi
	   if [[ $sstr =~ $3 ]];then
       flag=2
	   fi
   fi
   if [ $flag -eq 2 ];then
       continue
   fi
   if [ $cnt -eq 0 ];then
      if [ $flag -eq 0 ];then
        destIP=$fstr
	   else
	    destIP=$sstr
	   fi
   else
      if [ $flag -eq 0 ];then
        tmpIP=$fstr
	   else
	    tmpIP=$sstr
	   fi
	   if [[ $destIP =~ $tmpIP ]];then
          continue
	   else
	      destIP=${destIP}"\\n"$tmpIP
       fi
   fi
   cnt=$(($cnt+1))
  done < $checkfile
  echo -e $destIP >> $tmpfile
  validnum=`cat $tmpfile|wc -l`
  if [ $validnum -gt 200 ];then
      rm ../$checkfile
  fi
  rm $checkfile
  cp ./$tmpfile ./$checkfile
  cp ./$tmpfile ./$1$addpre
  rm $tmpfile
  sleep 40m
else
  cp ../$checkfile ./$tmp2file
    cnt=0;
  while read -r line
  do
   flag=0;
   fstr=`echo $line | cut -d \  -f 1`
   sstr=`echo $line | cut -d \  -f 2`
   if [[ $fstr =~ $2 ]];then
       flag=1
       if [[ $sstr =~ $2 ]];then
       flag=2
	   fi
	   if [[ $sstr =~ $3 ]];then
       flag=2
	   fi
   fi
   if [[ $fstr =~ $3 ]];then
       flag=1
       if [[ $sstr =~ $2 ]];then
       flag=2
	   fi
	   if [[ $sstr =~ $3 ]];then
       flag=2
	   fi
   fi
   if [ $flag -eq 2 ];then
       continue
   fi
   if [ $cnt -eq 0 ];then
      if [ $flag -eq 0 ];then
        destIP=$fstr
	   else
	    destIP=$sstr
	   fi
   else
      if [ $flag -eq 0 ];then
        tmpIP=$fstr
	   else
	    tmpIP=$sstr
	   fi
	   if [[ $destIP =~ $tmpIP ]];then
          continue
	   else
	      destIP=${destIP}"\n"$tmpIP
       fi
   fi
   cnt=$(($cnt+1))
  done < $tmp2file
  echo -e $destIP >> $tmpfile
  
  validnum=`cat $tmpfile|wc -l`
  if [ $validnum -gt 200 ];then
      rm ../$checkfile
  fi
  rm $tmp2file

  rm $1$addpre
  rm $1$delpre
  proDel=""
  cnt=0;
  while read -r line
  do
    flag=0
	echo $line
	while read -r line2
	do 
	  if [[ $line2 =~ $line ]];then
	  flag=1
	  break
	  fi
	  if [[ $line =~ $line2 ]];then
	  flag=1
	  break
	  fi
	done < $tmpfile
	if [ $flag -eq 1 ];then
	   continue
	fi
	if [ $cnt -eq 0 ];then
	     proDel=$line
	else
	     proDel=${proDel}"\n"$line
	fi
	cnt=$(($cnt+1))
  done < $checkfile
  echo -e $proDel >> $1$delpre
  
  
  proAdd=""
  cnt=0;
  while read -r line
  do
    flag=0
    while read -r line2
	do 
	  if [[ $line2 =~ $line ]];then
	  flag=1
	  break
	  fi
	  if [[ $line =~ $line2 ]];then
	  flag=1
	  break
	  fi
	done < $checkfile
	if [ $flag -eq 1 ];then
	   continue
	fi
	if [ $cnt -eq 0 ];then
	     proAdd=$line
	else
	     proAdd=${proAdd}"\n"$line
	fi
	cnt=$(($cnt+1))
  done < $tmpfile
  echo -e $proAdd >> $1$addpre
  rm ./$checkfile
  cp ./$tmpfile ./$checkfile
  rm $tmpfile
  sleep 40m
fi






