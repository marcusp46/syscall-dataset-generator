#!/bin/bash

sudo /opt/java/bin/java -agentlib:jdwp=transport=dt_shmem,server=y,suspend=n docker_container $1 $2
