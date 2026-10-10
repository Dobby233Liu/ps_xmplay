TARGET = xmplayer
TYPE = ps-exe
BUILD ?= LTO

XM_BUILTIN ?= true
XM_DIR ?= retail
XM_TYPE_MUSIC = 0
XM_TYPE_SFX = 1
XM_PANNING_XM = 0
XM_PANNING_S3M = 1

ifeq ($(XM_BUILTIN),true)
XM ?=

XM_TYPE ?= $(XM_TYPE_MUSIC)
XM_LOOP ?= 1
XM_POSITION ?= 0
XM_PANNING_TYPE ?= $(XM_PANNING_XM)

SONG_DIR = ../songdata/$(XM_DIR)/
subsym = $(subst /,_,$(subst .,_,$(subst -,_,$(1))))
XM_FILENAME_SYM := $(call subsym,$(XM_DIR)/$(XM))
# This also kind of makes sure the file is always built
TARGET := xmplayer_$(XM_FILENAME_SYM)
endif

XMPLAY_VARIANT ?= sbspss
XMPLAY_ENABLE_FIXES ?=

SRCS = \
nugget/common/crt0/crt0.s \
nugget/common/syscalls/printf.s
ifeq ($(XMPLAY_VARIANT),redriver2)
SRCS += xmplay/src/xmplay.c
endif
SRCS += debug.c \
main.c \
song.c

ifeq ($(XM_BUILTIN),true)
SONG_OBJ_ROOT = songobjs/
ifneq ($(XM),)
OBJS += $(SONG_OBJ_ROOT)$(XM_FILENAME_SYM)_xm.o $(SONG_OBJ_ROOT)$(XM_FILENAME_SYM)_vh.o \
	$(SONG_OBJ_ROOT)$(XM_FILENAME_SYM)_vb.o
endif
endif

CPPFLAGS += -Inugget -Ipsyq/include -Ixmplay/include
ifeq ($(XM_BUILTIN),true)
CPPFLAGS += -DXM_BUILTIN=1 -DXM_TYPE="$(XM_TYPE)" -DXM_LOOP="$(XM_LOOP)" \
-DXM_POSITION="$(XM_POSITION)" -DXM_PANNING_TYPE="$(XM_PANNING_TYPE)"
endif

ifeq ($(XMPLAY_VARIANT),sbspss)
CPPFLAGS += -DXMPLAY_VARIANT_SBSPSS
endif
ifeq ($(XMPLAY_VARIANT),redriver2)
CPPFLAGS += -DXMPLAY_VARIANT_REDRIVER2
ifneq ($(XMPLAY_ENABLE_FIXES),)
CPPFLAGS += -DXMPLAY_ENABLE_FIXES
endif
endif

CPPFLAGS += -Wall -Wextra -Wno-unused-function -Wpedantic

LDFLAGS += -Lpsyq/lib -Lxmplay/lib
LDFLAGS += -Wl,--start-group -lc -lapi -letc -lgpu -lspu
ifneq ($(XMPLAY_VARIANT),)
ifneq ($(XMPLAY_VARIANT),redriver2)
LDFLAGS += -lxmplay_$(XMPLAY_VARIANT)
else
LDFLAGS += -lsnd
endif
else
LDFLAGS += -lxmplay_46
endif
LDFLAGS += -Wl,--end-group

include nugget/common.mk

ifeq ($(XM_BUILTIN),true)
define SONG_TO_OBJ
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 \
		--rename-section .data=.rodata,alloc,load,readonly,data,contents \
		--redefine-sym _binary_$(call subsym,$(1))_start=_song_$(2)_start \
		-O $(FORMAT) -B mips $(1) $@
endef

$(SONG_OBJ_ROOT):
	mkdir "$@"

$(SONG_OBJ_ROOT)$(XM_FILENAME_SYM)_xm.o: $(SONG_DIR)$(XM).xm $(SONG_OBJ_ROOT)
	$(call SONG_TO_OBJ,$<,xm)

$(SONG_OBJ_ROOT)$(XM_FILENAME_SYM)_vh.o: $(SONG_DIR)$(XM).vh $(SONG_OBJ_ROOT)
	$(call SONG_TO_OBJ,$<,vh)

$(SONG_OBJ_ROOT)$(XM_FILENAME_SYM)_vb.o: $(SONG_DIR)$(XM).vb $(SONG_OBJ_ROOT)
	$(call SONG_TO_OBJ,$<,vb)

.PHONY: clean-songdata
clean-songdata:
	rm -rf "$(SONG_OBJ_ROOT)"

clean:: clean-songdata
endif
