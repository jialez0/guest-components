#!/bin/bash
REPO_PREFIX=tng-registry.cn-shanghai.cr.aliyuncs.com/dev/trustiflux

docker build -t $REPO_PREFIX:confidential-data-hub -f Dockerfile.cdh . --push
# docker build -t $REPO_PREFIX:attestation-agent -f Dockerfile.aa . --push