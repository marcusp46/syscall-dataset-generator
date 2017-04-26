#!/bin/bash

echo VISITING $1 $2 $3
PORT=$(($2 + 5901))
CID_FILE=${3}.cid
rm -rf $CID_FILE
echo $PORT is port math, $CID_FILE is cidfile
#sudo docker run --cidfile=$CID_FILE -t -i -p ${PORT}:5900 marcusp/firefox-vnc:latest /visit_url.sh $1 $3
echo TID:${2} "sudo docker run --cidfile=$CID_FILE -p ${PORT}:5900 marcusp/firefox-vnc:latest /visit_url.sh $1 $3"
sudo docker run --cidfile=$CID_FILE -p ${PORT}:5900 marcusp/firefox-vnc:latest /visit_url.sh $1 $3
#sudo docker run --cidfile=$CID_FILE -p 5900 marcusp/firefox-vnc:latest /visit_url.sh $1 $3
echo TID:${2} cid is $(cat $CID_FILE)
CID=$(cat $CID_FILE)
mkdir ./changes
sudo docker cp ${CID}:/strace_out/${3}.zip ./changes
sudo docker kill ${CID}
#zip ./changes/${3}.zip $CID_FILE
rm -rf $CID_FILE
#sudo docker run -t -i -p 5901:5900 marcusp/firefox-vnc:latest /bin/bash
#sleep 120
