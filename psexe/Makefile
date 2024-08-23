TARGET = xmplayer
TYPE = ps-exe

XM_BUILTIN ?= true
XM_DIR ?= retail
XM_TYPE_MUSIC = 0
XM_TYPE_SFX = 1
XM_PANNING_XM = 0
XM_PANNING_S3M = 1

ifeq ($(XM_BUILTIN),true)
include song.mk
endif

XMPLAY_VARIANT ?= sbspss
XMPLAY_WORSE_TIMING ?=

SONGDATA_OBJS = song_xm.o song_vh.o song_vb.o

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
SRCS += $(SONGDATA_OBJS)
endif

CPPFLAGS += -Inugget -Ipsyq/include -Ixmplay/include
ifeq ($(XM_BUILTIN),true)
CPPFLAGS += -DXM_DIR="$(subst /,_,$(subst .,_,$(subst -,_,$(XM_DIR))))" -DXM_FILENAME="$(subst .,_,$(subst -,_,$(XM)))" \
-DXM_TYPE="$(XM_TYPE)" -DXM_LOOP="$(XM_LOOP)" \
-DXM_POSITION="$(XM_POSITION)" -DXM_PANNING_TYPE="$(XM_PANNING_TYPE)"
endif

ifeq ($(XMPLAY_VARIANT),sbspss)
CPPFLAGS += -DXMPLAY_VARIANT_SBSPSS
ifneq ($(XMPLAY_WORSE_TIMING),)
CPPFLAGS += -DXMPLAY_WORSE_TIMING # HACK regret this
endif
endif
ifeq ($(XMPLAY_VARIANT),redriver2)
CPPFLAGS += -DXMPLAY_VARIANT_REDRIVER2
endif

LDFLAGS += -Lpsyq/lib -Lxmplay/lib
LDFLAGS += -Wl,--start-group -lc -lapi -letc -lgpu -lspu
ifneq ($(XMPLAY_VARIANT),)
ifneq ($(XMPLAY_VARIANT),redriver2)
LDFLAGS += -lxmplay_$(XMPLAY_VARIANT)
endif
else
LDFLAGS += -lxmplay_46
endif
LDFLAGS += -Wl,--end-group

include nugget/common.mk

ifeq ($(XM_BUILTIN),true)
define SONG_TO_OBJ
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $(1) $@
endef

# FIXME: can't rebuild with the XM filename changed

song_xm.o: ../songdata/$(XM_DIR)/$(XM).xm
	$(call SONG_TO_OBJ,$<)

song_vh.o: ../songdata/$(XM_DIR)/$(XM).vh
	$(call SONG_TO_OBJ,$<)

song_vb.o: ../songdata/$(XM_DIR)/$(XM).vb
	$(call SONG_TO_OBJ,$<)

.PHONY: clean-songdata
clean-songdata:
	rm -f $(SONGDATA_OBJS)
endif