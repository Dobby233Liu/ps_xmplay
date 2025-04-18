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
XM ?= chapter1

XM_TYPE ?= $(XM_TYPE_MUSIC)
XM_LOOP ?= 1
XM_POSITION ?= 0
XM_PANNING_TYPE ?= $(XM_PANNING_XM)

SONG_DIR = ../songdata/$(XM_DIR)/
XM_FILENAME_SYM = $(subst /,_,$(subst .,_,$(subst -,_,$(XM_DIR)/$(XM))))
# HACK to make sure the change is reflected
TARGET = xmplayer_$(XM_FILENAME_SYM)
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
OBJS += song_$(XM_FILENAME_SYM)_xm.o song_$(XM_FILENAME_SYM)_vh.o song_$(XM_FILENAME_SYM)_vb.o
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

#CPPFLAGS += -Wall -Wno-unused-function

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
		--redefine-sym _binary_$(subst /,_,$(subst .,_,$(subst -,_,$(1))))_start=_song_$(2)_start \
		-O $(FORMAT) -B mips $(1) $@
endef

song_$(XM_FILENAME_SYM)_xm.o: $(SONG_DIR)$(XM).xm
	$(call SONG_TO_OBJ,$<,xm)

song_$(XM_FILENAME_SYM)_vh.o: $(SONG_DIR)$(XM).vh
	$(call SONG_TO_OBJ,$<,vh)

song_$(XM_FILENAME_SYM)_vb.o: $(SONG_DIR)$(XM).vb
	$(call SONG_TO_OBJ,$<,vb)

.PHONY: clean-songdata
clean-songdata:
	rm -f song_*_xm.o song_*_vh.o song_*_vb.o

clean-all-exe:
	rm -f xmplayer_*.elf xmplayer_*.ps-exe

clean:: clean-songdata clean-all-exe
endif