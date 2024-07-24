from enum import IntEnum, auto

FILE_EQUATES = [
    "SYSTEM_CACHE",
    "SPRITES_SPRITES_SPR",
    "SHOP_SHOP_SPR",
    "PARTY_PARTY_SPR",
    "SCRIPTS_CH1L1_01_DAT",
    "SCRIPTS_CH1L1_02_DAT",
    "SCRIPTS_CH1L2_01_DAT",
    "SCRIPTS_CH1L2_02_DAT",
    "SCRIPTS_CH1L2_03_DAT",
    "SCRIPTS_CH1L4_01_DAT",
    "SCRIPTS_CH1L4_02_DAT",
    "SCRIPTS_CH2L1_01_DAT",
    "SCRIPTS_CH2L1_02_DAT",
    "SCRIPTS_CH2L2_01_DAT",
    "SCRIPTS_CH2L2_02_DAT",
    "SCRIPTS_CH3L2_01_DAT",
    "SCRIPTS_CH3L3_01_DAT",
    "SCRIPTS_CH3L3_02_DAT",
    "SCRIPTS_CH4L3_01_DAT",
    "SCRIPTS_CH4L3_02_DAT",
    "SCRIPTS_FMA_CH1_00_DAT",
    "SCRIPTS_FMA_CH1_01_DAT",
    "SCRIPTS_FMA_CH1_02_DAT",
    "SCRIPTS_FMA_CH1_03_DAT",
    "SCRIPTS_FMA_CH2_00_DAT",
    "SCRIPTS_FMA_CH2_01_DAT",
    "SCRIPTS_FMA_CH2_02_DAT",
    "SCRIPTS_FMA_CH2_03_DAT",
    "SCRIPTS_FMA_CH3_00_DAT",
    "SCRIPTS_FMA_CH3_01_DAT",
    "SCRIPTS_FMA_CH3_02_DAT",
    "SCRIPTS_FMA_CH4_00_DAT",
    "SCRIPTS_FMA_CH4_01_DAT",
    "SCRIPTS_FMA_CH4_02_DAT",
    "SCRIPTS_FMA_CH5_00_DAT",
    "SCRIPTS_FMA_CH5_01_DAT",
    "SCRIPTS_FMA_CH5_02_DAT",
    "SCRIPTS_FMA_CH6_00_DAT",
    "SCRIPTS_FMA_CH6_01_DAT",
    "SCRIPTS_FMA_CH6_02_DAT",
    "SCRIPTS_FMA_CH6_03_DAT",
    "SCRIPTS_FMA_PARTY_DAT",
    "SCRIPTS_FMA_PLANKTON_DAT",
    "SCRIPTS_C1L1_CELEBRATE_DAT",
    "SCRIPTS_C1L2_CELEBRATE_DAT",
    "SCRIPTS_C1L3_CELEBRATE_DAT",
    "SCRIPTS_C1L4_CELEBRATE_DAT",
    "SCRIPTS_C2L1_CELEBRATE_DAT",
    "SCRIPTS_C2L2_CELEBRATE_DAT",
    "SCRIPTS_C2L3_CELEBRATE_DAT",
    "SCRIPTS_C2L4_CELEBRATE_DAT",
    "SCRIPTS_C3L1_CELEBRATE_DAT",
    "SCRIPTS_C3L2_CELEBRATE_DAT",
    "SCRIPTS_C3L3_CELEBRATE_DAT",
    "SCRIPTS_C3L4_CELEBRATE_DAT",
    "SCRIPTS_C4L1_CELEBRATE_DAT",
    "SCRIPTS_C4L2_CELEBRATE_DAT",
    "SCRIPTS_C4L3_CELEBRATE_DAT",
    "SCRIPTS_C4L4_CELEBRATE_DAT",
    "SCRIPTS_C5L1_CELEBRATE_DAT",
    "SCRIPTS_C5L2_CELEBRATE_DAT",
    "SCRIPTS_C5L3_CELEBRATE_DAT",
    "SCRIPTS_C5L4_CELEBRATE_DAT",
    "SCRIPTS_TRIGGERSPEECH_151_DAT",
    "SCRIPTS_TRIGGERSPEECH_152_DAT",
    "SCRIPTS_TRIGGERSPEECH_153_DAT",
    "SCRIPTS_TRIGGERSPEECH_154_DAT",
    "SCRIPTS_TRIGGERSPEECH_155_DAT",
    "SCRIPTS_TRIGGERSPEECH_156_DAT",
    "SCRIPTS_TRIGGERSPEECH_157_DAT",
    "SCRIPTS_TRIGGERSPEECH_158_DAT",
    "SCRIPTS_TRIGGERSPEECH_159_DAT",
    "SCRIPTS_TRIGGERSPEECH_028_DAT",
    "TRANSLATIONS_SWE_DAT",
    "TRANSLATIONS_DUT_DAT",
    "TRANSLATIONS_ITA_DAT",
    "TRANSLATIONS_GER_DAT",
    "TRANSLATIONS_ID_DAT",
    "TRANSLATIONS_ENG_DAT",
    "MUSIC_CHAPTER1_PXM",
    "MUSIC_CHAPTER1_VB",
    "MUSIC_CHAPTER1_VH",
    "MUSIC_CHAPTER2_PXM",
    "MUSIC_CHAPTER2_VB",
    "MUSIC_CHAPTER2_VH",
    "MUSIC_CHAPTER3_PXM",
    "MUSIC_CHAPTER3_VB",
    "MUSIC_CHAPTER3_VH",
    "MUSIC_CHAPTER4_PXM",
    "MUSIC_CHAPTER4_VB",
    "MUSIC_CHAPTER4_VH",
    "MUSIC_CHAPTER5_PXM",
    "MUSIC_CHAPTER5_VB",
    "MUSIC_CHAPTER5_VH",
    "MUSIC_CHAPTER6_PXM",
    "MUSIC_CHAPTER6_VB",
    "MUSIC_CHAPTER6_VH",
    "MUSIC_SB_TITLE_PXM",
    "MUSIC_SB_TITLE_VB",
    "MUSIC_SB_TITLE_VH",
    "MUSIC_FMA_PXM",
    "MUSIC_FMA_VB",
    "MUSIC_FMA_VH",
    "SFX_INGAME_PXM",
    "SFX_INGAME_VB",
    "SFX_INGAME_VH",
    "DEMO_DEMO_____DMO",
    "BACKDROP_CREDITS_GFX",
    "BACKDROP_START1_GFX",
    "BACKDROP_START2_GFX",
    "BACKDROP_START3_GFX",
    "BACKDROP_START4_GFX",
    "BACKDROP_GAMEOVER_GFX",
    "BACKDROP_SHOP_GFX",
    "BACKDROP_PARTYBACKDROP_GFX",
    "BACKDROP_NICK_GFX",
    "LOADINGSCREENS_CULTURE_GFX",
    "LOADINGSCREENS_KARATE_GFX",
    "LOADINGSCREENS_MONITOR_GFX",
    "LOADINGSCREENS_PICKLES_GFX",
    "LOADINGSCREENS_PINEAPPLE_GFX",
    "LOADINGSCREENS_PIZZA_GFX",
    "LOADINGSCREENS_TEENAGE_GFX",
    "LOADINGSCREENS_BOOTSCREEN_GFX",
    "MEMCARD_MEMHEAD_BIN",
    "MAP_MAP_BACKGROUND_GFX",
    "MAP_C1_L1_GFX",
    "MAP_C1_L2_GFX",
    "MAP_C1_L3_GFX",
    "MAP_C1_L4_GFX",
    "MAP_C1_FAIR_GFX",
    "MAP_C2_L1_GFX",
    "MAP_C2_L2_GFX",
    "MAP_C2_L3_GFX",
    "MAP_C2_L4_GFX",
    "MAP_C2_FAIR_GFX",
    "MAP_C3_L1_GFX",
    "MAP_C3_L2_GFX",
    "MAP_C3_L3_GFX",
    "MAP_C3_L4_GFX",
    "MAP_C3_FAIR_GFX",
    "MAP_C4_L1_GFX",
    "MAP_C4_L2_GFX",
    "MAP_C4_L3_GFX",
    "MAP_C4_L4_GFX",
    "MAP_C4_FAIR_GFX",
    "MAP_C5_L1_GFX",
    "MAP_C5_L2_GFX",
    "MAP_C5_L3_GFX",
    "MAP_C5_L4_GFX",
    "MAP_C5_FAIR_GFX",
    "LEVELS_CHAPTER01_LEVEL01_LVL",
    "LEVELS_CHAPTER01_LEVEL01_TEX",
    "LEVELS_CHAPTER01_LEVEL02_LVL",
    "LEVELS_CHAPTER01_LEVEL02_TEX",
    "LEVELS_CHAPTER01_LEVEL03_LVL",
    "LEVELS_CHAPTER01_LEVEL03_TEX",
    "LEVELS_CHAPTER01_LEVEL04_LVL",
    "LEVELS_CHAPTER01_LEVEL04_TEX",
    "LEVELS_CHAPTER02_LEVEL01_LVL",
    "LEVELS_CHAPTER02_LEVEL01_TEX",
    "LEVELS_CHAPTER02_LEVEL02_LVL",
    "LEVELS_CHAPTER02_LEVEL02_TEX",
    "LEVELS_CHAPTER02_LEVEL03_LVL",
    "LEVELS_CHAPTER02_LEVEL03_TEX",
    "LEVELS_CHAPTER02_LEVEL04_LVL",
    "LEVELS_CHAPTER02_LEVEL04_TEX",
    "LEVELS_CHAPTER03_LEVEL01_LVL",
    "LEVELS_CHAPTER03_LEVEL01_TEX",
    "LEVELS_CHAPTER03_LEVEL02_LVL",
    "LEVELS_CHAPTER03_LEVEL02_TEX",
    "LEVELS_CHAPTER03_LEVEL03_LVL",
    "LEVELS_CHAPTER03_LEVEL03_TEX",
    "LEVELS_CHAPTER03_LEVEL04_LVL",
    "LEVELS_CHAPTER03_LEVEL04_TEX",
    "LEVELS_CHAPTER04_LEVEL01_LVL",
    "LEVELS_CHAPTER04_LEVEL01_TEX",
    "LEVELS_CHAPTER04_LEVEL02_LVL",
    "LEVELS_CHAPTER04_LEVEL02_TEX",
    "LEVELS_CHAPTER04_LEVEL03_LVL",
    "LEVELS_CHAPTER04_LEVEL03_TEX",
    "LEVELS_CHAPTER04_LEVEL04_LVL",
    "LEVELS_CHAPTER04_LEVEL04_TEX",
    "LEVELS_CHAPTER05_LEVEL01_LVL",
    "LEVELS_CHAPTER05_LEVEL01_TEX",
    "LEVELS_CHAPTER05_LEVEL02_LVL",
    "LEVELS_CHAPTER05_LEVEL02_TEX",
    "LEVELS_CHAPTER05_LEVEL03_LVL",
    "LEVELS_CHAPTER05_LEVEL03_TEX",
    "LEVELS_CHAPTER05_LEVEL04_LVL",
    "LEVELS_CHAPTER05_LEVEL04_TEX",
    "LEVELS_CHAPTER06_LEVEL01_LVL",
    "LEVELS_CHAPTER06_LEVEL01_TEX",
    "LEVELS_CHAPTER06_LEVEL02_LVL",
    "LEVELS_CHAPTER06_LEVEL02_TEX",
    "LEVELS_CHAPTER06_LEVEL03_LVL",
    "LEVELS_CHAPTER06_LEVEL03_TEX",
    "LEVELS_CHAPTER06_LEVEL04_LVL",
    "LEVELS_CHAPTER06_LEVEL04_TEX",
    "LEVELS_CHAPTER06_LEVEL05_LVL",
    "LEVELS_CHAPTER06_LEVEL05_TEX",
    "LEVELS_FMA_SHADYSHOALS_LVL",
    "LEVELS_FMA_SHADYSHOALS_TEX",
    "LEVELS_FMA_CONTROLROOM_LVL",
    "LEVELS_FMA_CONTROLROOM_TEX",
    "ACTORS_SPONGEBOB_SBK",
    "ACTORS_SPONGEBOB_CORALBLOWER_SBK",
    "ACTORS_SPONGEBOB_JELLYLAUNCHER_SBK",
    "ACTORS_SPONGEBOB_NET_SBK",
    "ACTORS_SPONGEBOB_WAND_SBK",
    "ACTORS_SPONGEBOB_JELLYFISH_SBK",
    "ACTORS_SPONGEBOB_GLOVE_SBK",
    "ACTORS_SPONGEBOB_FMA_SBK",
    "ACTORS_SPONGEBOB_FMA_ITEMOFS_SBK",
    "ACTORS_BARNACLEBOY_SBK",
    "ACTORS_BARNACLEBOY_FMA_ITEMOFS_SBK",
    "ACTORS_KRUSTY_SBK",
    "ACTORS_SQUIDWARD_SBK",
    "ACTORS_GARY_SBK",
    "ACTORS_SANDY_SBK",
    "ACTORS_PATRICK_SBK",
    "ACTORS_MERMAIDMAN_SBK",
    "ACTORS_MERMAIDMAN_FMA_ITEMOFS_SBK",
    "ACTORS_PLANKTON_SBK",
    "ACTORS_ANENOME_SBK",
    "ACTORS_BABYOCTOPUS_SBK",
    "ACTORS_BALLBLOB_SBK",
    "ACTORS_CATERPILLAR_SBK",
    "ACTORS_CLAM_SBK",
    "ACTORS_DUSTDEVIL_SBK",
    "ACTORS_FLAMINGSKULL_SBK",
    "ACTORS_FLYINGDUTCHMAN_SBK",
    "ACTORS_GHOST_SBK",
    "ACTORS_HERMITCRAB_SBK",
    "ACTORS_IRONDOGFISH_SBK",
    "ACTORS_PUFFAFISH_SBK",
    "ACTORS_MANRAY_SBK",
    "ACTORS_SKELETALFISH_SBK",
    "ACTORS_SPIDERCRAB_SBK",
    "ACTORS_SPIKEYANENOME_SBK",
    "ACTORS_STOMPER_SBK",
    "ACTORS_GIANTWORM_SBK",
    "ACTORS_SHARKSUB_SBK",
    "ACTORS_MOTHERJELLYFISH_SBK",
    "ACTORS_SEASNAKE_SBK",
]