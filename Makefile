CC = gcc
CFLAGS = -Wall -g
LIBS = -lcapstone
TARGET = rapl
SOURCES = main.c detect.c table.c

# Support for both macOS and iOS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    CFLAGS += -DDARWIN
endif

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

test: $(TARGET)
	@echo "Building test binaries..."
	@$(MAKE) -C tests/comprehensive -s
	@$(MAKE) -C tests/stack-clash -s
	@$(MAKE) -C tests/heap-cookies -s
	@$(MAKE) -C tests/integer-overflow -s
	@$(MAKE) -C tests/arc-test -s
	@$(MAKE) -C tests/encrypted-test -s
	@$(MAKE) -C tests/restrict-test -s
	@$(MAKE) -C tests/nx-heap-test -s
	@$(MAKE) -C tests/nx-stack-test -s
	@echo "Running security mitigation tests..."
	@./comprehensive_test.sh

static: $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) -L/usr/local/lib -lcapstone


clean:
	rm -f $(TARGET) *.o
	$(MAKE) -C tests/comprehensive clean
	$(MAKE) -C tests/stack-clash clean
	$(MAKE) -C tests/heap-cookies clean
	$(MAKE) -C tests/integer-overflow clean
	$(MAKE) -C tests/arc-test clean
	$(MAKE) -C tests/encrypted-test clean
	$(MAKE) -C tests/restrict-test clean
	$(MAKE) -C tests/nx-heap-test clean
	$(MAKE) -C tests/nx-stack-test clean

.PHONY: clean install test static

