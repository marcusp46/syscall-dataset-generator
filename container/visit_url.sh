#!/bin/bash

#start
RETURN_STATUS=0
declare -x LD_LIBRARY_PATH=$LD_LIBRARY_PATH:"/root/firefox"
rm -rf /strace_out
mkdir /strace_out
mkdir /strace_out/logs
cd /strace_out/logs
Xvfb -screen 0 1024x768x24 -ac &
sleep 3
declare -x DISPLAY=:0
x11vnc -forever &
#sleep 5
fvwm &
#sleep 5
#open strace.sh firefox-vn
/pin-2.14-71313-gcc.4.4.7-linux/source/tools/strace/strace.sh /root/firefox/firefox $1 &
PIN_ID=$!
echo $PIN_ID
#firefox $1 &
sleep 600

kill -s SIGTERM $PIN_ID

#for aid in $(ls lock_*.out); do
#	APP_PID=$(cat $aid| head -n 1)
#	echo $APP_PID is terminating
#	kill -s SIGTERM $APP_PID
#	kill -s SIGKILL $APP_PID
#	wait $APP_PID
#done

pkill firefox
wait $PIN_ID

sleep 10
cd /strace_out

for null_check in $(ls thread_*.out psh*.out context*.out); do
	if ! [ -s $null_check ]; then
		touch error_null_file
		RETURN_STATUS=1
	fi
done

zip -r /strace_out/${2}.zip .
exit $RETURN_STATUS
