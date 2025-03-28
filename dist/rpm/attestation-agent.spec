
%global _prefix /usr/local
%global config_dir /etc/trustiflux

Name:           Attestation-Agent
Version:        0.0.3
Release:        2%{?dist}
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

# Prepare tpm2-tss sources
pushd guest-components/dist/tpm-deps
tar xf tpm2-tss-2.4.6.tar.gz
pushd tpm2-tss-2.4.6

./configure --disable-doxygen-doc --with-pkgconfigdir='/usr/lib64/pkgconfig'
popd
popd

%build
mkdir -p ./guest-components && pushd guest-components
cargo build -p attestation-agent --bin ttrpc-aa --release --no-default-features --features bin,ttrpc,rust-crypto,coco_as,kbs,tpm-attester --target x86_64-unknown-linux-gnu
cargo build -p attestation-agent --bin ttrpc-aa-client --release --no-default-features --features bin,ttrpc,rust-crypto,coco_as,kbs,tpm-attester --target x86_64-unknown-linux-gnu

# Build tpm2-tss
pushd dist/tpm-deps/tpm2-tss-2.4.6
make -j4
popd

%install
pushd guest-components
install -d -p %{buildroot}%{_prefix}/lib/systemd/system
install -m 644 dist/rpm/attestation-agent.service %{buildroot}%{_prefix}/lib/systemd/system/attestation-agent.service
install -d -p %{buildroot}/etc/trustiflux
install -m 644 dist/rpm/attestation-agent.toml %{buildroot}%{config_dir}/attestation-agent.toml
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa %{buildroot}%{_prefix}/bin/attestation-agent
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa-client %{buildroot}%{_prefix}/bin/attestation-agent-client

# Install tpm2-tss
pushd dist/tpm-deps/tpm2-tss-2.4.6
make install DESTDIR=%{buildroot}
popd

%ldconfig_scriptlets

%post
systemctl daemon-reload
/sbin/ldconfig

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

# Add tpm2-tss files
/usr/lib64/pkgconfig/tss2-*.pc
/usr/local/etc/sysusers.d/tpm2-tss.conf
/usr/local/etc/tmpfiles.d/tpm2-tss-fapi.conf
/usr/local/etc/tpm2-tss/fapi-config.json
/usr/local/etc/tpm2-tss/fapi-profiles/P_*.json
/usr/local/include/tss2/tss2_*.h
/usr/local/lib/libtss2-*.a
/usr/local/lib/libtss2-*.la
/usr/local/lib/libtss2-*.so
/usr/local/lib/libtss2-*.so.0
/usr/local/lib/libtss2-*.so.0.0.0
/usr/local/lib/udev/rules.d/tpm-udev.rules
/usr/local/share/man/man3/Tss2_Tcti*.3
/usr/local/share/man/man5/fapi-*.5
/usr/local/share/man/man7/tss2-tcti*.7


%changelog
* Fri Apr 30 2025 Jiale Zhang <zhangjiale@linux.alibaba.com> - 0.0.3-2
- Integrated tpm2-tss version 2.4.6