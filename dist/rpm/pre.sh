yum install -y \
  cargo \
  gcc \
  autoconf \
  automake \
  libtool \
  git \
  openssl-devel \
  json-c-devel \
  libcurl-devel \
  make \
  doxygen \
  libgcrypt libgcrypt-devel \
  perl-IPC-Cmd \
  clang clang-devel \

cd /tmp
curl https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/distro/Anolis86/sgx_rpm_local_repo.tgz --output sgx_rpm_local_repo.tgz && \
    tar zxvf sgx_rpm_local_repo.tgz && \
    find /etc/yum.repos.d/ -type f -exec sed -i 's/http:\/\/mirrors.openanolis.cn\/anolis/https:\/\/mirrors.aliyun.com\/anolis/g' {} + && \
    yum -y install yum-utils && yum-config-manager --add-repo file:///tmp/sgx_rpm_local_repo && \
    yum install -y --setopt=install_weak_deps=False --nogpgcheck libtdx-attest-devel perl wget curl clang openssl-devel protobuf-devel git libudev-devel && \
    yum clean all