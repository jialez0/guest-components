#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o nounset
set -o pipefail

[ -n "${BASH_VERSION:-}" ] && set -o errtrace
[ -n "${DEBUG:-}" ] && set -o xtrace

if ! command -v cargo >/dev/null 2>&1; then
    if [ -n "${CARGO_HOME:-}" ] && [ -f "${CARGO_HOME}/env" ]; then
        source "${CARGO_HOME}/env"
    elif [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    else
        echo >&2 "ERROR: cargo not found in PATH and no cargo env script is available"
        exit 1
    fi
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CDH_DIR=$SCRIPT_DIR/../../confidential-data-hub

pushd $CDH_DIR

make RESOURCE_PROVIDER=none KMS_PROVIDER=none RPC="${RPC}"
make DESTDIR="${SCRIPT_DIR}/${RPC}" install

file "${SCRIPT_DIR}/${RPC}/confidential-data-hub"
popd
