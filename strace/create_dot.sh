#!/usr/bin/bash

for i in $(ls *.dot); do

dot -Tpng $i > ${i}.png

done;
