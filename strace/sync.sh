#!/usr/bin/bash

cp PrintSyscallAdjMatrix/x64/Release/Cluster.exe PrintSyscallAdjMatrix/Release/Cluster64.exe
rsync.exe -avz  PrintSyscallAdjMatrix/Release/ jankins@129.115.191.254:/home/jankins/Release/
#rsync.exe -avz  Cluster/ jankins@129.115.191.254:/home/jankins/Cluster/
















