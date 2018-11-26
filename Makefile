LIBRARY = libdisspcap.so
SRC_EXT = cc
HEADER_EXT = h
SRC_PATH = src
BUILD_PATH = build
CC = g++
DEBUG = -g

CFLAGS = -fPIC -std=c++11 -pedantic -Wall -Wextra
LDFLAGS = -lpcap -lpthread

SOURCES = $(shell find $(SRC_PATH) -name '*.$(SRC_EXT)' -not -name '*python*')
INCLUDES = $(shell find $(SRC_PATH) -name '*.$(HEADER_EXT)' -not -name '*python*')
OBJECTS = $(SOURCES:$(SRC_PATH)/%.$(SRC_EXT)=$(BUILD_PATH)/%.o)
OBJ_FOLDERS = $(shell dirname $(OBJECTS) | sort | uniq)

all: dirs $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	@echo "Linking..."
	$(CC) $(DEBUG) $(CFLAGS) $^ -shared -o $(LIBRARY) $(LDFLAGS)

$(BUILD_PATH)/%.o: $(SRC_PATH)/%.$(SRC_EXT)
	@echo "Compiling..."
	$(CC) $(CFLAGS) $(DEBUG) -c -o $@ $<

dirs:
	@echo "Creating directory structure..."
	mkdir -p $(OBJ_FOLDERS)

clean:
	@echo "Removing object files and binaries..."
	rm -rf $(BUILD_PATH) $(PROGRAM)

.PHONY: clean