CC = /usr/bin/clang
CFLAGS_BASE = -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk -framework Foundation

# ARC enabled
ARC_FLAGS = -fobjc-arc

# ARC disabled (manual memory management)
NO_ARC_FLAGS = -fno-objc-arc

all: test_arc_enabled test_arc_disabled

test_arc_enabled: test_arc_enabled.m
	$(CC) $(CFLAGS_BASE) $(ARC_FLAGS) -o test_arc_enabled test_arc_enabled.m

test_arc_disabled: test_arc_disabled.m
	$(CC) $(CFLAGS_BASE) $(NO_ARC_FLAGS) -o test_arc_disabled test_arc_disabled.m

clean:
	rm -f test_arc_enabled test_arc_disabled

.PHONY: all clean