# SPDX-License-Identifier: LGPL-3.0-or-later

# pyServer and the pre-trained model must be installed on the system. See README for details.

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: pyServer.manifest 
ifeq ($(SGX),1)
all: pyServer.manifest.sgx pyServer.sig
endif

pyServer.manifest: pyServer.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v python3")) \
		-Drdir=$(realpath $(shell sh -c "command pwd")) \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# for details on this workaround see
# https://github.com/gramineproject/gramine/blob/e8735ea06c/CI-Examples/helloworld/Makefile
pyServer.manifest.sgx pyServer.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: pyServer.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx


.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest 

.PHONY: distclean
distclean: clean
	$(RM) *.pt result.txt