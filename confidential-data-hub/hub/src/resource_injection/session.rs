// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use kbs_protocol::TeeKeyPair;

pub(super) struct InjectionSession {
    pub(super) resource_path: String,
    pub(super) tee_key: TeeKeyPair,
}
