// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Error, Result};

pub(super) const KBS_RESOURCE_STORAGE_DIR: &str = "/run/confidential-containers/cdh";

pub(super) fn validate_resource_path(resource_path: &str) -> Result<()> {
    if !is_relative_resource_path_valid(resource_path) {
        return Err(Error::ResourceInjection(format!(
            "invalid resource path: {resource_path}"
        )));
    }

    Ok(())
}

fn is_relative_resource_path_valid(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|it| it.is_empty() || it == ".." || it == ".")
}
