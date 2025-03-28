%global _prefix /usr/local
%global config_dir /etc/trustiflux

Name:           confidential-data-hub
Version:        0.0.1
Release:        1%{?dist}
Summary:        A daemon service running inside TEE (Trusted Execution Environment) to provide attestation related APIs
Group:          Applications/System
BuildArch:      x86_64

License:        Apache-2.0

%description
Confidential Data Hub is a daemon service running inside TEE (Trusted Execution Environment) to provide confidential resource related APIs.

%prep
find . -mindepth 1 -delete
mkdir -p ./guest-components
cp -af `find %{expand:%%(pwd)}/ -maxdepth 1 -mindepth 1 | grep -vE target` ./guest-components

%build
mkdir -p ./guest-components && pushd guest-components
cargo build -p confidential-data-hub --release --bin cdh-oneshot --no-default-features --features "bin,aliyun,kbs" --target x86_64-unknown-linux-gnu

%install
pushd guest-components
install -d -p %{buildroot}/etc/trustiflux
install -m 644 dist/rpm/confidential-data-hub.toml %{buildroot}%{config_dir}/confidential-data-hub.toml
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/x86_64-unknown-linux-gnu/release/cdh-oneshot %{buildroot}%{_prefix}/bin/confidential-data-hub

%files
%{_prefix}/bin/confidential-data-hub
%{config_dir}/confidential-data-hub.toml

%changelog
* Fri Oct 10 2025 Jiale Zhang <zhangjiale@linux.alibaba.com> - 0.0.1-1
- Initial Release