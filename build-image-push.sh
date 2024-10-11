#!/bin/bash
REPO_PREFIX=registry.cn-beijing.aliyuncs.com/lxx/trustiflux

# e.g. 20240903
tag=$(date +%Y%m%d)

docker build -t $REPO_PREFIX:confidential-data-hub-${tag} -t $REPO_PREFIX:confidential-data-hub-latest -f Dockerfile.cdh . --push
docker build -t $REPO_PREFIX:attestation-agent-${tag} -t $REPO_PREFIX:attestation-agent-latest -f Dockerfile.aa . --push