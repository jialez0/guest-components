#!/bin/bash

ARCH=${ARCH:-x86_64}

mkdir -p dist/build
sudo -E docker run -it --rm -v $(pwd):/home/gc --network host \
    -v ~/.ssh:/root/.ssh \
    confidential-ai-registry.cn-shanghai.cr.aliyuncs.com/dev/attestation-agent-rpm:0.0.1 \
    sh -c "cd /home/gc && rpmbuild -ba /home/gc/dist/rpm/attestation-agent.spec && cp /root/rpmbuild/RPMS/${ARCH}/* /home/gc/dist/build/"
