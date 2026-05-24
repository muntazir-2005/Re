CC = xcrun -sdk iphoneos clang
ARCHS = arm64
SDK = $(shell xcrun -sdk iphoneos --show-sdk-path)

# تمت إضافة -I. لتضمين المجلد الحالي في مسارات البحث عن headers
CFLAGS = -arch $(ARCHS) -isysroot $(SDK) -miphoneos-version-min=12.0 -fobjc-arc -O2 -I.

LDFLAGS = -dynamiclib -install_name @executable_path/ANOGS.dylib -lc++
FRAMEWORKS = -framework Foundation -framework UIKit -framework LocalAuthentication -framework Security

SRC = ANOGS.mm fishhook.c
OBJ = $(SRC:.c=.o)
OBJ := $(OBJ:.mm=.o)

all: ANOGS.dylib

ANOGS.dylib: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(FRAMEWORKS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.mm
	$(CC) $(CFLAGS) -x objective-c++ -c $< -o $@

clean:
	rm -f $(OBJ) ANOGS.dylib
