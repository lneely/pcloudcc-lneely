CC		:= gcc
CXX		:= g++
AR		:= ar

DIST_CFLAGS	:= $(CFLAGS)
DIST_CXXFLAGS	:= $(CXXFLAGS)

# Detect FUSE version (can be overridden with FORCE_FUSE=2 or FORCE_FUSE=3)
ifdef FORCE_FUSE
    ifeq ($(FORCE_FUSE),2)
        FUSE_VERSION := FUSE2
    else ifeq ($(FORCE_FUSE),3)
        FUSE_VERSION := FUSE3
    else
        $(error FORCE_FUSE must be 2 or 3)
    endif
else
    FUSE_VERSION := $(shell ./detect_fuse.sh)
endif

ifeq ($(FUSE_VERSION),FUSE3)
    FUSE_CFLAGS := $(shell pkg-config --cflags fuse3 2>/dev/null || echo "-I/usr/include/fuse3 -D_FILE_OFFSET_BITS=64")
    FUSE_LIBS := -lfuse3
    FUSE_USE_VERSION := 30
else ifeq ($(FUSE_VERSION),FUSE2)
    FUSE_CFLAGS := $(shell pkg-config --cflags fuse 2>/dev/null || echo "-I/usr/include/fuse -D_FILE_OFFSET_BITS=64")
    FUSE_LIBS := -lfuse
    FUSE_USE_VERSION := 26
else
    $(error FUSE library not found. Install libfuse-dev or libfuse3-dev)
endif

COMMONFLAGS	= -fsanitize=address
CFLAGS		= -fPIC $(COMMONFLAGS) -I./pclsync -I/usr/include $(FUSE_CFLAGS) $(shell pkg-config --cflags $$(pkg-config --list-all | grep -o 'mbedtls[0-9.]*\s' | head -1) 2>/dev/null || pkg-config --cflags mbedtls 2>/dev/null || echo "-I/usr/local/include")
ifneq (,$(filter clang%,$(CC)))
    CFLAGS += -Wthread-safety
endif
CXXFLAGS	= $(CFLAGS)
LIBLDFLAGS	= $(COMMONFLAGS) -lreadline -lpthread -ludev -lsqlite3 -lz $(shell \
	MBEDTLS_PKG=$$(pkg-config --list-all 2>/dev/null | grep -o 'mbedtls[0-9.]*\s' | head -1 | tr -d ' '); \
	if [ -n "$$MBEDTLS_PKG" ]; then \
		MBEDX509=$$(echo $$MBEDTLS_PKG | sed 's/mbedtls/mbedx509/'); \
		MBEDCRYPTO=$$(echo $$MBEDTLS_PKG | sed 's/mbedtls/mbedcrypto/'); \
		pkg-config --libs $$MBEDTLS_PKG $$MBEDX509 $$MBEDCRYPTO 2>/dev/null; \
	else \
		pkg-config --libs mbedtls mbedx509 mbedcrypto 2>/dev/null || echo "-L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto"; \
	fi)
EXECLDFLAGS	= $(COMMONFLAGS) -lboost_program_options $(FUSE_LIBS)

SCAN		:= 0
SRCDIR 		:= .
LIBDIR		:= pclsync

CSRC		:= $(wildcard $(LIBDIR)/*.c)
COBJ		:= $(notdir $(CSRC:%.c=%.o))
CPPSRC		:= $(wildcard $(SRCDIR)/*.cpp)
CPPOBJ		:= $(notdir $(CPPSRC:%.cpp=%.o))

DESTDIR		:= /usr/local
STATIC		:= 1
FULLSTATIC	:= 0
BUILD		:= release
SSLDBGLVL   := 0

EXECOUT		:= pcloudcc
LIBOUT		:= libpcloudcc_lib.so

# Build type specific flags
ifeq ($(BUILD), debug)
    CFLAGS += -g -O0 -DDEBUG -Wall -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=$(FUSE_USE_VERSION) -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
    CXXFLAGS += -g -O0 -DDEBUG -Wall -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=$(FUSE_USE_VERSION) -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
    DEBUGSRC := $(wildcard $(LIBDIR)/debug/*.c)
    DEBUGOBJ := $(notdir $(DEBUGSRC:%.c=%.o))
    COBJ += $(DEBUGOBJ)
else ifeq ($(BUILD), release)
    CFLAGS += -O2 -DNDEBUG -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=$(FUSE_USE_VERSION) -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
    CXXFLAGS += -O2 -DNDEBUG -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=$(FUSE_USE_VERSION) -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
    COMMONFLAGS := $(filter-out -fsanitize=address,$(COMMONFLAGS))
    LIBLDFLAGS := $(filter-out -fsanitize=address,$(LIBLDFLAGS))
    EXECLDFLAGS := $(filter-out -fsanitize=address,$(EXECLDFLAGS))
else
    $(error Invalid BUILD. Use 'debug' or 'release')
endif

ifeq ($(FULLSTATIC), 1)
    # Force static linking of all libraries
    LIBLDFLAGS += -static
    EXECLDFLAGS += -static
endif

CFLAGS		+= $(DIST_CFLAGS)
CXXFLAGS	+= $(DIST_CXXFLAGS)
LIBLDFLAGS	+= $(LDFLAGS)
EXECLDFLAGS	+= $(LDFLAGS)

ifeq ($(SCAN), 1)
	CC := scan-build -o scanresults $(CC)
	CXX := scan-build -o scanresults $(CXX)
endif

TARGETS := $(EXECOUT)
ifeq ($(STATIC), 0)
	TARGETS += $(LIBOUT)
	EXECLDFLAGS += -L. -lpcloudcc_lib
else
	EXECLDFLAGS += $(LIBLDFLAGS)
endif

.PHONY: all clean install install-logrotate uninstall

all: $(TARGETS)

clean:
	rm -f $(COBJ) $(CPPOBJ) $(EXECOUT) $(LIBOUT)

$(EXECOUT): $(CPPOBJ) $(if $(filter 0,$(STATIC)),$(LIBOUT),$(COBJ))
	$(CXX) -o $@ $(CPPOBJ) $(if $(filter 0,$(STATIC)),,$(COBJ)) $(EXECLDFLAGS)

$(CPPOBJ): %.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(DEBUGOBJ): %.o: $(LIBDIR)/debug/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(filter-out $(DEBUGOBJ),$(COBJ)): %.o: $(LIBDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBOUT): $(COBJ)
	$(CC) -shared -fPIC -o $@ $^ $(LIBLDFLAGS)

install:
	install -m 755 pcloudcc $(DESTDIR)/bin/pcloudcc
ifeq ($(STATIC), 0)
	install -m 755 libpcloudcc_lib.so $(DESTDIR)/lib/libpcloudcc_lib.so
endif

install-logrotate:
	@echo "Installing logrotate configuration (requires root)..."
	install -D -m 644 pcloudcc.logrotate /etc/logrotate.d/pcloudcc
	@echo "Logrotate configuration installed to /etc/logrotate.d/pcloudcc"
	@echo "Note: This handles system-wide logs at /var/log/pcloudcc.log"
	@echo "For user-specific logs, see comments in pcloudcc.logrotate"

uninstall:
	rm -f $(DESTDIR)/bin/pcloudcc
	rm -f $(DESTDIR)/lib/libpcloudcc_lib.so
	rm -f /etc/logrotate.d/pcloudcc

# ---------------------------------------------------------------------------
# Unit tests — link against actual production code from pclsync/
# ---------------------------------------------------------------------------
UNIT_DIR := tests/unit-tests
TESTS_DIR := tests

TEST_CFLAGS  := -D_POSIX_C_SOURCE=200809L
TEST_CXXFLAGS := -D_POSIX_C_SOURCE=200809L

HELPERS_DIR := tests/helpers

TEST_BINS := \
	tests/test_pdbg_path \
	tests/test_ptools_params \
	tests/test_pfs_lock_ordering \
	tests/test_ptask_free \
	tests/test_prun \
	tests/test_ptools_errptr \
	tests/test_read_response \
	tests/test_signal_safety \
	tests/test_ptree \
	tests/test_pintervaltree \
	tests/test_pfstasks_tree \
	tests/test_pfstasks_db

.PHONY: test tests check clean-tests

test: check

tests: $(TEST_BINS)

check: tests
	@rc=0; \
	for t in $(TEST_BINS); do \
		echo "=== $$t ==="; \
		$$t || rc=$$?; \
	done; \
	exit $$rc

clean-tests:
	rm -f $(TEST_BINS)

tests/test_pdbg_path: $(UNIT_DIR)/test_pdbg_path.c $(LIBDIR)/pdbg.c $(LIBDIR)/pmem.c $(LIBDIR)/putil.c $(LIBDIR)/ppath.c tests/stubs/test_stubs.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $^

tests/test_ptools_params: $(UNIT_DIR)/test_ptools_params.c $(LIBDIR)/ptools.c $(LIBDIR)/pdbg.c $(LIBDIR)/pmem.c $(LIBDIR)/putil.c $(LIBDIR)/ppath.c tests/stubs/test_stubs.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $^

tests/test_pfs_lock_ordering: $(UNIT_DIR)/test_pfs_lock_ordering.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $< -lpthread

tests/test_ptask_free: $(UNIT_DIR)/test_ptask_free.c $(LIBDIR)/ptask_free.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $^ \
		-Wl,--wrap=pthread_mutex_lock \
		-Wl,--wrap=pthread_mutex_unlock \
		-Wl,--wrap=pmem_free \
		-lpthread

tests/test_prun: $(UNIT_DIR)/test_prun.c $(LIBDIR)/prun.c $(LIBDIR)/pdbg.c $(LIBDIR)/pmem.c $(LIBDIR)/putil.c $(LIBDIR)/ppath.c tests/stubs/test_stubs.c
	$(CC) -D_POSIX_C_SOURCE=199309L $(CFLAGS) -o $@ $^ \
		-Wl,--wrap=pthread_create \
		-Wl,--wrap=pthread_attr_destroy \
		-Wl,--wrap=malloc \
		-Wl,--wrap=free \
		-lpthread

tests/test_ptools_errptr: $(UNIT_DIR)/test_ptools_errptr.c $(LIBDIR)/ptools.c $(LIBDIR)/pdbg.c $(LIBDIR)/pmem.c $(LIBDIR)/putil.c $(LIBDIR)/ppath.c tests/stubs/test_stubs.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $^ \
		-Wl,--wrap=malloc \
		-Wl,--wrap=free

tests/test_ptree: $(UNIT_DIR)/test_ptree.c $(LIBDIR)/ptree.c $(LIBDIR)/pdbg.c $(LIBDIR)/pmem.c $(LIBDIR)/putil.c $(LIBDIR)/ppath.c tests/stubs/test_stubs.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $^

tests/test_pintervaltree: $(UNIT_DIR)/test_pintervaltree.c $(LIBDIR)/pintervaltree.c $(LIBDIR)/ptree.c $(LIBDIR)/pdbg.c $(LIBDIR)/pmem.c $(LIBDIR)/putil.c $(LIBDIR)/ppath.c tests/stubs/test_stubs.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $^

tests/test_pfstasks_tree: $(UNIT_DIR)/test_pfstasks_tree.c $(LIBDIR)/pfstasks_tree.c $(LIBDIR)/ptree.c $(LIBDIR)/pdbg.c $(LIBDIR)/pmem.c $(LIBDIR)/putil.c $(LIBDIR)/ppath.c tests/stubs/test_stubs.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -o $@ $^

tests/test_pfstasks_db: $(UNIT_DIR)/test_pfstasks_db.c $(HELPERS_DIR)/psql_test_helpers.c
	$(CC) $(TEST_CFLAGS) $(CFLAGS) -I$(HELPERS_DIR) -o $@ $^ -lsqlite3

tests/test_read_response: $(UNIT_DIR)/test_read_response.cpp rpcclient.cpp tests/stubs/test_stubs_cpp.c
	$(CXX) $(TEST_CXXFLAGS) $(CXXFLAGS) -o $@ $^

tests/test_signal_safety: $(TESTS_DIR)/test_signal_safety.c
	$(CC) -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -o $@ $< -lpthread -lrt
