TEE_PLATFORM ?= none
AS ?=
ARCH ?= $(shell uname -m)

DESTDIR ?= /usr/local/bin

LIBC ?= musl
ATTESTERS ?=

NO_RESOURCE_PROVIDER ?=

ifeq ($(NO_RESOURCE_PROVIDER), true)
  RESOURCE_PROVIDER :=
else
  RESOURCE_PROVIDER ?= kbs
endif

ifeq ($(TEE_PLATFORM), none)
  ATTESTERS := 
else ifeq ($(TEE_PLATFORM), tdx)
  LIBC = gnu
  ATTESTERS = tdx
else ifeq ($(TEE_PLATFORM), tdx)
  ATTESTERS = snp
else ifeq ($(TEE_PLATFORM), az-tdx-vtpm)
  ATTESTERS = az_tdx_vtpm
else ifeq ($(TEE_PLATFORM), az-snp-vtpm)
  ATTESTERS = az_snp_vtpm
else ifeq ($(TEE_PLATFORM), sev)
  ATTESTERS = 
  ifeq ($(NO_RESOURCE_PROVIDER), true)
    RESOURCE_PROVIDER :=
  else
    RESOURCE_PROVIDER = sev
  endif
endif
# TODO: Add support for CCA and CSV

ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
  LIBC = gnu
endif

CDH := confidential-data-hub
AA := attestation-agent
ASR := api-server-rest

BUILD_DIR := target/$(ARCH)-unknown-linux-$(LIBC)/release

CDH_BINARY := $(BUILD_DIR)/$(CDH)
AA_BINARY := $(BUILD_DIR)/$(AA)
ASR_BINARY := $(BUILD_DIR)/$(ASR)

build: $(CDH_BINARY) $(ASR_BINARY) $(AA_BINARY)
	@echo guest components built for $(TEE_PLATFORM) succeeded!

$(CDH_BINARY):
	@echo build $(CDH) for $(TEE_PLATFORM)
	cd $(CDH) && $(MAKE) RESOURCE_PROVIDER=$(RESOURCE_PROVIDER) LIBC=$(LIBC)

$(AA_BINARY):
	@echo build $(AA) for $(TEE_PLATFORM)
	cd $(AA) && $(MAKE) ttrpc=true ARCH=$(ARCH) LIBC=$(LIBC) AS=$(AS) ATTESTERS=$(ATTESTERS)

$(ASR_BINARY):
	@echo build $(ASR) for $(TEE_PLATFORM)
	cd $(ASR) && $(MAKE) ARCH=$(ARCH) LIBC=$(LIBC)

install: $(CDH_BINARY) $(ASR_BINARY) $(AA_BINARY)
	install -D -m0755 $(CDH_BINARY) $(DESTDIR)/$(CDH)
	install -D -m0755 $(AA_BINARY) $(DESTDIR)/$(AA)
	install -D -m0755 $(ASR_BINARY) $(DESTDIR)/$(ASR)

clean:
	rm -rf target
