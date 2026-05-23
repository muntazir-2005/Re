CC = xcrun -sdk iphoneos clang
ARCHS = arm64
SDK = $(shell xcrun -sdk iphoneos --show-sdk-path)
CFLAGS = -arch $(ARCHS) -isysroot $(SDK) -miphoneos-version-min=12.0 -fobjc-arc -O2
LDFLAGS = -dynamiclib -install_name @executable_path/ANOGS.dylib
FRAMEWORKS = -framework Foundation -framework UIKit -framework LocalAuthentication -framework Security

SRC = ANOGS.mm fishhook.c
OBJ = $(SRC:.c=.o)
OBJ := $(OBJ:.mm=.o)

all: ANOGS.dylib

ANOGS.dylib: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(FRAMEWORKS)   # <-- استخدمنا CFLAGS بدل ARCHS

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.mm
	$(CC) $(CFLAGS) -x objective-c++ -c $< -o $@

clean:
	rm -f $(OBJ) ANOGS.dylib
