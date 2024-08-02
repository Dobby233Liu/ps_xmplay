TARGET = xmplayer
TYPE = ps-exe

XM_BUILTIN ?= false
XM_DIR ?= songdata
XM_TYPE_MUSIC = 0
XM_TYPE_SFX = 1
XM_PANNING_XM = 0
XM_PANNING_S3M = 1

ifeq ($(XM_BUILTIN),true)
include song.mk
endif

XMPLAY_VARIANT ?= sbspss # 2000/08

SONGDATA_OBJS = song_xm.o song_vh.o song_vb.o

SRCS = \
nugget/common/crt0/crt0.s \
nugget/common/syscalls/printf.s \
debug.c \
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
#CPPFLAGS += -DXMPLAY_WORSE_TIMING # HACK regret this
endif
LDFLAGS += -Lpsyq/lib -Lxmplay/lib
LDFLAGS += -Wl,--start-group -lc -lapi -letc -lgpu -lspu
ifneq ($(XMPLAY_VARIANT),)
LDFLAGS += -lxmplay_$(XMPLAY_VARIANT)
else
LDFLAGS += -lxmplay
endif
LDFLAGS += -Wl,--end-group

include nugget/common.mk

ifeq ($(XM_BUILTIN),true)
define SONG_TO_OBJ
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $(1) $@
endef

# FIXME: can't rebuild

song_xm.o: ../$(XM_DIR)/$(XM).xm
	$(call SONG_TO_OBJ,$<)

song_vh.o: ../$(XM_DIR)/$(XM).vh
	$(call SONG_TO_OBJ,$<)

song_vb.o: ../$(XM_DIR)/$(XM).vb
	$(call SONG_TO_OBJ,$<)

.PHONY: clean-songdata
clean-songdata:
	rm -f $(SONGDATA_OBJS)
endif