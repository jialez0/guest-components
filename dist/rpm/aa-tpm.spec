%global _prefix /usr/local
%global config_dir /etc/trustiflux

Name:           Attestation-Agent
Version:        0.0.5
Release:        1%{?dist}
Summary:        A daemon service running inside TEE (Trusted Execution Environment) to provide attestation related APIs
Group:          Applications/System
BuildArch:      x86_64

License:        Apache-2.0

%description
Attestation Agent is a daemon service running inside TEE (Trusted Execution Environment) to provide attestation related APIs.

%prep
find . -mindepth 1 -delete
mkdir -p ./guest-components
cp -af `find %{expand:%%(pwd)}/ -maxdepth 1 -mindepth 1 | grep -vE target` ./guest-components

%build
mkdir -p ./guest-components && pushd guest-components
cargo build -p attestation-agent --bin ttrpc-aa --release --no-default-features --features bin,ttrpc,rust-crypto,coco_as,kbs,tpm-attester,instance_info --target x86_64-unknown-linux-gnu
cargo build -p attestation-agent --bin ttrpc-aa-client --release --no-default-features --features bin,ttrpc,eventlog,rust-crypto,coco_as,kbs,tpm-attester --target x86_64-unknown-linux-gnu

%install
pushd guest-components
install -d -p %{buildroot}%{_prefix}/lib/systemd/system
install -m 644 dist/rpm/attestation-agent.service %{buildroot}%{_prefix}/lib/systemd/system/attestation-agent.service
install -d -p %{buildroot}/etc/trustiflux
install -m 644 dist/rpm/attestation-agent.toml %{buildroot}%{config_dir}/attestation-agent.toml
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa %{buildroot}%{_prefix}/bin/attestation-agent
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa-client %{buildroot}%{_prefix}/bin/attestation-agent-client

%ldconfig_scriptlets

%post
systemctl daemon-reload
echo '/usr/local/lib' | tee /etc/ld.so.conf.d/usr-local-lib.conf && ldconfig

%postun
if [ $1 == 0 ]; then #uninstall
  systemctl daemon-reload
  systemctl reset-failed
fi

%files
%{_prefix}/bin/attestation-agent
%{_prefix}/bin/attestation-agent-client
%{config_dir}/attestation-agent.toml
%{_prefix}/lib/systemd/system/attestation-agent.service

%changelog
* Fri Oct 10 2025 Jiale Zhang <zhangjiale@linux.alibaba.com> - 0.0.5-1
- Initial Release