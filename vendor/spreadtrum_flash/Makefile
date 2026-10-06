
LIBUSB = 1
CFLAGS ?= -O2 -Wall -Wextra -std=c99 -pedantic
CFLAGS += -DUSE_LIBUSB=$(LIBUSB)
APPNAME = spd_dump

ifeq ($(LIBUSB), 1)
CPPFLAGS += $(shell pkg-config --cflags libusb-1.0)
LIBS = $(shell pkg-config --libs libusb-1.0)
endif

.PHONY: all clean test
all: $(APPNAME)

clean:
	$(RM) $(APPNAME) protocol_tests

$(APPNAME): $(APPNAME).c spd_cmd.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

protocol_tests: protocol_tests.c spd_dump.c spd_cmd.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

test: protocol_tests
	./protocol_tests
