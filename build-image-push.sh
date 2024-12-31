#!/bin/bash
REPO_PREFIX=registry.cn-hangzhou.aliyuncs.com/lxx/trustiflux

docker build -t $REPO_PREFIX:confidential-data-hub-20240821 -f Dockerfile.cdh . --push
# docker build -t $REPO_PREFIX:attestation-agent -f Dockerfile.aa . --push