# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Pattern rule to print variables, e.g. make print-top_srcdir
print-%:
	@echo '$*' = '$($*)'

ACLOCAL_AMFLAGS = -I build-aux/m4
SUBDIRS = src
if ENABLE_MAN
SUBDIRS += doc/man
endif
.PHONY: deploy FORCE

export PYTHONPATH

if BUILD_BITCOIN_LIBS
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbitcoinconsensus.pc
endif

BITCOIND_BIN=$(top_builddir)/src/$(BITCOIN_DAEMON_NAME)$(EXEEXT)
BITCOIN_QT_BIN=$(top_builddir)/src/qt/$(BITCOIN_GUI_NAME)$(EXEEXT)
BITCOIN_CLI_BIN=$(top_builddir)/src/$(BITCOIN_CLI_NAME)$(EXEEXT)
BITCOIN_TX_BIN=$(top_builddir)/src/$(BITCOIN_TX_NAME)$(EXEEXT)
BITCOIN_WIN_INSTALLER=$(PACKAGE)-$(PACKAGE_VERSION)-win64-setup$(EXEEXT)

empty :=
space := $(empty) $(empty)

OSX_APP=PRCYcoin-Qt.app
OSX_VOLNAME = $(subst $(space),-,$(PACKAGE_NAME))
OSX_DMG = $(OSX_VOLNAME).dmg
OSX_DEPLOY_SCRIPT=$(top_srcdir)/contrib/macdeploy/macdeployqtplus
OSX_INSTALLER_ICONS=$(top_srcdir)/src/qt/res/icons/bitcoin.icns
OSX_PLIST=$(top_builddir)/share/qt/Info.plist #not installed

DIST_DOCS = \
  README.md \
  $(wildcard doc/*.md) \
  $(wildcard doc/release-notes/*.md)
DIST_CONTRIB = $(top_srcdir)/contrib/prcycoin-cli.bash-completion \
	       $(top_srcdir)/contrib/prcycoin-tx.bash-completion \
	       $(top_srcdir)/contrib/prcycoind.bash-completion \
           $(top_srcdir)/contrib/init \
           $(top_srcdir)/contrib/install_db4.sh

DIST_SHARE = \
           $(top_srcdir)/share/genbuild.sh \
           $(top_srcdir)/share/rpcauth
		   
BIN_CHECKS=$(top_srcdir)/contrib/devtools/symbol-check.py \
           $(top_srcdir)/contrib/devtools/security-check.py

WINDOWS_PACKAGING = $(top_srcdir)/share/pixmaps/prcycoin.ico \
  $(top_srcdir)/share/pixmaps/nsis-header.bmp \
  $(top_srcdir)/share/pixmaps/nsis-wizard.bmp \
  $(top_srcdir)/doc/README_windows.txt

LINUX_PACKAGING = $(top_srcdir)/share/pixmaps/prcycoin16.xpm \
  $(top_srcdir)/share/pixmaps/prcycoin32.xpm \
  $(top_srcdir)/share/pixmaps/prcycoin128.png

OSX_PACKAGING = $(OSX_DEPLOY_SCRIPT) $(OSX_INSTALLER_ICONS) \
  $(top_srcdir)/contrib/macdeploy/detached-sig-apply.sh \
  $(top_srcdir)/contrib/macdeploy/detached-sig-create.sh

COVERAGE_INFO = baseline.info \
  test_prcycoin_filtered.info total_coverage.info \
  baseline_filtered.info functional_test.info functional_test_filtered.info \
  test_prcycoin_coverage.info test_prcycoin.info

dist-hook:
	-$(GIT) archive --format=tar HEAD -- src/clientversion.cpp | $(AMTAR) -C $(top_distdir) -xf -

$(BITCOIN_WIN_INSTALLER): all-recursive
	$(MKDIR_P) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIND_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_QT_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_CLI_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_TX_BIN) $(top_builddir)/release
	@test -f $(MAKENSIS) && $(MAKENSIS) -V2 $(top_builddir)/share/setup.nsi || \
	  echo error: could not build $@
	@echo built $@

$(OSX_APP)/Contents/PkgInfo:
	$(MKDIR_P) $(@D)
	@echo "APPL????" > $@

$(OSX_APP)/Contents/Resources/empty.lproj:
	$(MKDIR_P) $(@D)
	@touch $@

$(OSX_APP)/Contents/Info.plist: $(OSX_PLIST)
	$(MKDIR_P) $(@D)
	$(INSTALL_DATA) $< $@

$(OSX_APP)/Contents/Resources/bitcoin.icns: $(OSX_INSTALLER_ICONS)
	$(MKDIR_P) $(@D)
	$(INSTALL_DATA) $< $@

$(OSX_APP)/Contents/MacOS/PRCYcoin-Qt: all-recursive
	$(MKDIR_P) $(@D)
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM)  $(BITCOIN_QT_BIN) $@

$(OSX_APP)/Contents/Resources/Base.lproj/InfoPlist.strings:
	$(MKDIR_P) $(@D)
	echo '{	CFBundleDisplayName = "$(PACKAGE_NAME)"; CFBundleName = "$(PACKAGE_NAME)"; }' > $@

OSX_APP_BUILT=$(OSX_APP)/Contents/PkgInfo $(OSX_APP)/Contents/Resources/empty.lproj \
  $(OSX_APP)/Contents/Resources/bitcoin.icns $(OSX_APP)/Contents/Info.plist \
  $(OSX_APP)/Contents/MacOS/PRCYcoin-Qt $(OSX_APP)/Contents/Resources/Base.lproj/InfoPlist.strings

osx_volname:
	echo $(OSX_VOLNAME) >$@

if BUILD_DARWIN
$(OSX_DMG): $(OSX_APP_BUILT) $(OSX_PACKAGING)
	$(PYTHON) $(OSX_DEPLOY_SCRIPT) $(OSX_APP) $(OSX_VOLNAME) -translations-dir=$(QT_TRANSLATION_DIR) -dmg

deploydir: $(OSX_DMG)
else
APP_DIST_DIR=$(top_builddir)/dist

$(OSX_DMG): deploydir
	$(XORRISOFS) -D -l -V "$(OSX_VOLNAME)" -no-pad -r -dir-mode 0755 -o $@ dist -- $(if $(SOURCE_DATE_EPOCH),-volume_date all_file_dates =$(SOURCE_DATE_EPOCH))

$(APP_DIST_DIR)/$(OSX_APP)/Contents/MacOS/PRCYcoin-Qt: $(OSX_APP_BUILT) $(OSX_PACKAGING)
	INSTALL_NAME_TOOL=$(INSTALL_NAME_TOOL) OTOOL=$(OTOOL) STRIP=$(STRIP) $(PYTHON) $(OSX_DEPLOY_SCRIPT) $(OSX_APP) $(OSX_VOLNAME) -translations-dir=$(QT_TRANSLATION_DIR)

deploydir: $(APP_DIST_DIR)/$(OSX_APP)/Contents/MacOS/PRCYcoin-Qt
endif

if TARGET_DARWIN
deploy: $(OSX_DMG)
endif
if TARGET_WINDOWS
deploy: $(BITCOIN_WIN_INSTALLER)
endif

$(BITCOIN_QT_BIN): FORCE
	$(MAKE) -C src qt/$(@F)

$(BITCOIND_BIN): FORCE
	$(MAKE) -C src $(@F)

$(BITCOIN_CLI_BIN): FORCE
	$(MAKE) -C src $(@F)

$(BITCOIN_TX_BIN): FORCE
	$(MAKE) -C src $(@F)

if USE_LCOV
LCOV_FILTER_PATTERN=-p "/usr/include/" -p "/usr/lib/" -p "src/leveldb/" -p "src/crc32c/" -p "src/univalue" -p "src/secp256k1" -p "src/secp256k1-mw"

baseline.info:
	$(LCOV) -c -i -d $(abs_builddir)/src -o $@

baseline_filtered.info: baseline.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

test_prcycoin.info: baseline_filtered.info
	$(MAKE) -C src/ check
	$(LCOV) -c $(LCOV_OPTS) -d $(abs_builddir)/src -t test_prcycoin -o $@
	$(LCOV) -z $(LCOV_OPTS) -d $(abs_builddir)/src

test_prcycoin_filtered.info: test_prcycoin.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

functional_test.info: test_prcycoin_filtered.info
	-@TIMEOUT=15 test/functional/test_runner.py $(EXTENDED_FUNCTIONAL_TESTS)
	$(LCOV) -c $(LCOV_OPTS) -d $(abs_builddir)/src --t functional-tests -o $@
	$(LCOV) -z $(LCOV_OPTS) -d $(abs_builddir)/src

functional_test_filtered.info: functional_test.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

test_prcycoin_coverage.info: baseline_filtered.info test_prcycoin_filtered.info
	$(LCOV) -a $(LCOV_OPTS) baseline_filtered.info -a test_prcycoin_filtered.info -o $@

total_coverage.info: test_prcycoin_filtered.info functional_test_filtered.info
	$(LCOV) -a $(LCOV_OPTS) baseline_filtered.info -a test_prcycoin_filtered.info -a functional_test_filtered.info -o $@ | $(GREP) "\%" | $(AWK) '{ print substr($$3,2,50) "/" $$5 }' > coverage_percent.txt

test_prcycoin.coverage/.dirstamp:  test_prcycoin_coverage.info
	$(GENHTML) -s $(LCOV_OPTS) $< -o $(@D)
	@touch $@

total.coverage/.dirstamp: total_coverage.info
	$(GENHTML) -s $(LCOV_OPTS) $< -o $(@D)
	@touch $@

cov: test_prcycoin.coverage/.dirstamp total.coverage/.dirstamp

endif

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = $(DIST_SHARE) test/functional/test_runner.py test/functional $(DIST_CONTRIB) $(DIST_DOCS) $(WINDOWS_PACKAGING) $(LINUX_PACKAGING) $(OSX_PACKAGING) $(BIN_CHECKS)

#EXTRA_DIST += \
    #test/functional

EXTRA_DIST += \
    test/util/bitcoin-util-test.py \
    test/util/data/bitcoin-util-test.json \
    test/util/data/blanktxv1.hex \
    test/util/data/blanktxv1.json \
    test/util/data/tt-delin1-out.hex \
    test/util/data/tt-delin1-out.json \
    test/util/data/tt-delout1-out.hex \
    test/util/data/tt-delout1-out.json \
    test/util/data/tt-locktime317000-out.hex \
    test/util/data/tt-locktime317000-out.json \
    test/util/data/tx394b54bb.hex \
    test/util/data/txcreate1.hex \
    test/util/data/txcreate1.json \
    test/util/data/txcreate2.hex \
    test/util/data/txcreate2.json \
    test/util/data/txcreatescript1.hex \
    test/util/data/txcreatescript1.json \
    test/util/data/txcreatesign.hex \
    test/util/data/txcreatesign.json \
    test/util/rpcauth-test.py

CLEANFILES = $(OSX_DMG) $(BITCOIN_WIN_INSTALLER)

.INTERMEDIATE: $(COVERAGE_INFO)

DISTCHECK_CONFIGURE_FLAGS = --enable-man

doc/doxygen/.stamp: doc/Doxyfile FORCE
	$(MKDIR_P) $(@D)
	$(DOXYGEN) $^
	$(AM_V_at) touch $@

if HAVE_DOXYGEN
docs: doc/doxygen/.stamp
else
docs:
	@echo "error: doxygen not found"
endif

clean-docs:
	rm -rf doc/doxygen

clean-local: clean-docs
	rm -rf coverage_percent.txt test_prcycoin.coverage/ total.coverage/ test/tmp/ cache/ $(OSX_APP)
	rm -rf test/functional/__pycache__ test/functional/test_framework/__pycache__ test/cache share/rpcauth/__pycache__
	rm -rf osx_volname dist/
