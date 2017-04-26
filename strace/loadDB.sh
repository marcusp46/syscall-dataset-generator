#!/usr/bin/bash


LOGDIR=$1
TMPDIR=.
CSVEXE="/cygdrive/c/Users/mba737/Desktop/pin-2.14-71313-msvc12-windows/pin-2.14-71313-msvc12-windows/source/tools/strace/PrintSyscallAdjMatrix/Release/PrintSyscallAdjMatrix.exe"
DBEXE="/cygdrive/c/Users/mba737/Desktop/pin-2.14-71313-msvc12-windows/pin-2.14-71313-msvc12-windows/source/tools/strace/PrintSyscallAdjMatrix/Release/CSVtoDB.exe"


#
j=0
for i in $(ls ${LOGDIR}/*.zip); do 
#	mkdir $TMPDIR
	unzip -o -j -d $TMPDIR $i logs/array_dump.out 
	$CSVEXE array_dump.out
	$DBEXE array_dump.csv thread.db 0000
	((j=$j+1))
	echo $j>&2
done
