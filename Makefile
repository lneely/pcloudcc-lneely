CC			:= gcc
CXX			:= g++
AR			:= ar
COMMONFLAGS	= -fsanitize=address
CFLAGS		= -fPIC -g $(COMMONFLAGS) -I./pclsync -I/usr/include -I/usr/include/mbedtls2
ifneq (,$(filter clang%,$(CC)))
    CFLAGS += -Wthread-safety
endif
CXXFLAGS	= $(CFLAGS)
LIBLDFLAGS	= $(COMMONFLAGS) -lpthread -ludev -lsqlite3 -lz -l:libmbedtls.so.14 -l:libmbedx509.so.1 -l:libmbedcrypto.so.7
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
BUILD		:= release

EXECOUT		:= pcloudcc
LIBOUT		:= libpcloudcc_lib.so

# Build type specific flags
ifeq ($(BUILD), debug)
    CFLAGS += -O0 -DDEBUG
    CXXFLAGS += -O0 -DDEBUG
else ifeq ($(BUILD), release)
    CFLAGS += -O2 -DNDEBUG
    CXXFLAGS += -O2 -DNDEBUG
    COMMONFLAGS := $(filter-out -fsanitize=address,$(COMMONFLAGS))
    LIBLDFLAGS := $(filter-out -fsanitize=address,$(LIBLDFLAGS))
    EXECLDFLAGS := $(filter-out -fsanitize=address,$(EXECLDFLAGS))
else
    $(error Invalid BUILD. Use 'debug' or 'release')
endif

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

.PHONY: all clean install uninstall

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

uninstall:
	rm -f $(DESTDIR)/bin/pcloudcc
	rm -f $(DESTDIR)/lib/libpcloudcc_lib.so
