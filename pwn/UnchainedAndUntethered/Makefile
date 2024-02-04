
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

TOOL_PREFIX=
CC=$(TOOL_PREFIX)gcc
LD=$(TOOL_PREFIX)ld

ifdef TOOL_PREFIX
$(call allow-override,CC,$(CC))
$(call allow-override,LD,$(LD))
endif

NO_RELRO=-Wl,-z,norelro

CDEBUG=-g -O0
CFLAGS=-Iinclude -Isrc
LDFLAGS=


BINARY=main

BIN_UNTETHERED=untethered
BIN_UNCHAINED=unchained

BUILD_DIR=build
DEBUG_DIR=debug
RELEASE_DIR=release
OBJ=$(BUILD_DIR)

OBJECTS += src/main.o

RELEASE_OBJECT_FILES=$(addprefix $(OBJ)/release/, $(OBJECTS))
DBG_OBJECT_FILES=$(addprefix $(OBJ)/debug/, $(OBJECTS))

.PHONY: all clean tests debug release

all: debug release

$(OBJ)/$(DEBUG_DIR)/%.o: CFLAGS += $(CDEBUG)
$(OBJ)/$(DEBUG_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/$(RELEASE_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/$(DEBUG_DIR)/src/unchained.o: LDFLAGS += $(NO_RELRO)
$(OBJ)/$(DEBUG_DIR)/src/unchained.o: CFLAGS += $(CDEBUG)
$(OBJ)/$(DEBUG_DIR)/src/unchained.o: src/main.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/$(DEBUG_DIR)/src/untethered.o: CFLAGS += $(CDEBUG)
$(OBJ)/$(DEBUG_DIR)/src/untethered.o: src/main.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/$(RELEASE_DIR)/src/unchained.o: src/main.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/$(RELEASE_DIR)/src/untethered.o: src/main.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<


$(OBJ)/$(DEBUG_DIR)/$(BIN_UNCHAINED): LDFLAGS += $(NO_RELRO)
$(OBJ)/$(DEBUG_DIR)/$(BIN_UNCHAINED): $(OBJ)/$(DEBUG_DIR)/src/unchained.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CDEBUG) -o $@ $^ $(LDFLAGS)

$(OBJ)/$(DEBUG_DIR)/$(BIN_UNTETHERED): $(OBJ)/$(DEBUG_DIR)/src/untethered.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

debug: $(OBJ)/$(DEBUG_DIR)/$(BIN_UNCHAINED) $(OBJ)/$(DEBUG_DIR)/$(BIN_UNTETHERED)


$(OBJ)/$(RELEASE_DIR)/$(BIN_UNCHAINED): LDFLAGS += $(NO_RELRO)
$(OBJ)/$(RELEASE_DIR)/$(BIN_UNCHAINED): $(OBJ)/$(RELEASE_DIR)/src/unchained.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ)/$(RELEASE_DIR)/$(BIN_UNTETHERED): $(OBJ)/$(RELEASE_DIR)/src/untethered.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

release: $(OBJ)/$(RELEASE_DIR)/$(BIN_UNCHAINED) $(OBJ)/$(RELEASE_DIR)/$(BIN_UNTETHERED)

clean:
	rm -rf $(OBJ) 2>/dev/null
	rm -f $(BINARY) 2>/dev/null
