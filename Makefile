CC			:= clang
CXX			:= clang++
AR			:= ar
COMMONFLAGS	:= -fsanitize=address
CFLAGS		:= -fPIC -g $(COMMONFLAGS) -I./pclsync -I/usr/include -I/usr/include/mbedtls2 -O0
ifneq (,$(filter clang%,$(CC)))
    CFLAGS += -Wthread-safety
endif
CXXFLAGS	:= $(CFLAGS)
LIBLDFLAGS	:= $(COMMONFLAGS) -lpthread -ludev -lsqlite3 -lz -l:libmbedtls.so.14 -l:libmbedx509.so.1 -l:libmbedcrypto.so.7
EXECLDFLAGS	:= $(COMMONFLAGS) -lboost_program_options -lfuse

SCAN		:= 0
SRCDIR 		:= .
LIBDIR		:= pclsync

CSRC		:= $(wildcard $(LIBDIR)/*.c)
COBJ		:= $(notdir $(CSRC:%.c=%.o))
CPPSRC		:= $(wildcard $(SRCDIR)/*.cpp)
CPPOBJ		:= $(notdir $(CPPSRC:%.cpp=%.o))

DESTDIR		:= /usr/local
STATIC		:= 1

EXECOUT		:= pcloudcc
LIBOUT		:= libpcloudcc_lib.so

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

.PHONY: all clean

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
