#!/bin/bash
declare -x DISPLAY=:0
PIN_ROOT=/home/marcusp/src/pin-2.14-71313-gcc.4.4.7-linux/
${PIN_ROOT}/source/tools/strace/clean.sh
#${PIN_ROOT}/pin.sh -p64 ${PIN_ROOT}/intel64/bin/pinbin  -follow_execv -t ${PIN_ROOT}source/tools/strace/obj-intel64/strace.so -- $@
#${PIN_ROOT}/intel64/bin/pinbin  -injection child -follow_execv -t ${PIN_ROOT}source/tools/strace/obj-intel64/strace.so -- $@
#BELOW IS IDEAL
#${PIN_ROOT}/intel64/bin/pinbin  -follow_execv -t ${PIN_ROOT}source/tools/strace/obj-intel64/strace.so -- $@
${PIN_ROOT}/pin.sh  -follow_execv -t ${PIN_ROOT}source/tools/strace/obj-intel64/strace.so -- $@
#${PIN_ROOT}/intel64/bin/pinbin  -t ${PIN_ROOT}source/tools/strace/obj-intel64/strace.so -- $@
#${PIN_ROOT}/intel64/bin/pinbin   -- $@
#${PIN_ROOT}/intel64/bin/pinbin  -follow_execv -- $@
