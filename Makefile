CC		:= gcc
CXX		:= g++
AR		:= ar

DIST_CFLAGS	:= $(CFLAGS)
DIST_CXXFLAGS	:= $(CXXFLAGS)

COMMONFLAGS	= -fsanitize=address
CFLAGS		= -fPIC $(COMMONFLAGS) -I./pclsync -I/usr/include
ifneq (,$(filter clang%,$(CC)))
    CFLAGS += -Wthread-safety
endif
CXXFLAGS	= $(CFLAGS)
LIBLDFLAGS	= $(COMMONFLAGS) -lreadline -lpthread -ludev -lsqlite3 -lz -lmbedtls -lmbedx509 -lmbedcrypto
EXECLDFLAGS	= $(COMMONFLAGS) -lboost_program_options -lfuse

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
    CFLAGS += -g -O0 -DDEBUG -Wall -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
    CXXFLAGS += -g -O0 -DDEBUG -Wall -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
else ifeq ($(BUILD), release)
    CFLAGS += -O2 -DNDEBUG -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
    CXXFLAGS += -O2 -DNDEBUG -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -D_GNU_SOURCE -DPSYNC_SSL_DEBUG_LEVEL=$(SSLDBGLVL)
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

$(COBJ): %.o: $(LIBDIR)/%.c
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
