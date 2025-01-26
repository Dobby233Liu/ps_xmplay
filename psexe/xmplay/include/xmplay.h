#pragma once

extern int JPPer;

extern int XMTime1;
extern int XMTime2;
extern int XMTime3;

// dobby: Added in SBSPSS version
#define XM_PROCESSING 0
#define XM_NOT_PROCESSED 1

#define XM_NTSC 0				/* Machine type */
#define XM_PAL 1

#define XM_Loop 1				/* Looping song */
#define XM_NoLoop 0			/* Once off song */

#define XM_Music 0			/* Playback as music */
#define XM_SFX 1				/* Playback as SFX */

#define XM_UseXMPanning 0	/* S3M Panning switches */
#define XM_UseS3MPanning 1

#define XM_STOPPED 0			/* Song/SFX Status */
#define XM_PLAYING 1
#define XM_PAUSED  2

extern int XM_SCAN;			/* Scan lines used */
extern int JPError;			/* Test */


typedef struct XM_HeaderInfo
{
		unsigned short	BPM;
		unsigned short	Speed;
} XM_HeaderInfo;

typedef struct XM_VABInfo
{
		unsigned char*		Address;
		unsigned long		Size;
} XM_VABInfo;

typedef struct XM_Feedback
{
		unsigned char	Volume;
		short		Panning;
		int		CurrentStart;
		short		PlayNext;
		unsigned short	SongLength;
		unsigned char	Status;
		unsigned short	PatternPos;
		short		SongPos;
		unsigned short	CurrentPattern;
		unsigned short	SongSpeed;
		unsigned short	SongBPM;
		int		SongLoop;
		int		ActiveVoices;
} XM_Feedback;

void XM_Restart(int Song_ID);
void XM_Pause(int Song_ID);
void XM_Exit(void);
void XM_Update(void);
void XM_PlayStop(int Song_ID);
void XM_PlayStart(int Song_ID,int PlayMask);
void XM_SetSongPos(int Song_ID,unsigned short pos);
int InitXMData(unsigned char *mpp,int XM_ID,int S3MPan);
int XM_VABInit(unsigned char* VHData,unsigned char* VBData);
void XM_OnceOffInit(int PAL);
// dobby: Return type was labeled as void in the SDK 4.6 version
int XM_GetFeedback(int Song_ID,XM_Feedback* Feedback);
void XM_GetHeaderInfo(int XM_ID,XM_HeaderInfo* HeaderInfo);
int  XM_Init(int VabID,int XM_ID,int SongID, int FirstCh,
				 int Loop,int PlayMask,int PlayType,int SFXNum);
int XM_GetChVolume(int Song_ID,int Channel);
void XM_SetChVolume(int Song_ID,int Channel,int Volume);
void XM_PlayNext(int Song_ID,short SongPos);
void XM_CPlayNext(int Song_ID,short SongPos);
void XM_CloseVAB(int VabID);
void XM_SetMasterPan(int Song_ID,short Pan);
void XM_SetMasterVol(int Song_ID,unsigned char Vol);
int XM_SendVAGToSRAM(unsigned char *addr,int size);
int XM_SendVAGToSRAM_NoWait(unsigned char *addr,int size);
void XM_FreeVAG(int addr);
void UpdateWithTimer(int SC);
void XM_DoFullUpdate(int SC);

void XM_Quit(int SongID);
int XM_SetSFXRange(int FirstCh,int Amount);
void XM_ClearSFXRange(void);

void XM_StopSample(int channel);
void XM_PlaySample(int addr,int channel,int voll,int volr,int pitch);
int XM_GetSampleAddress(int vabid,int samplenum);
int XM_GetFreeVAB(void);
void XM_SetVAGAddress(int VabID,int slot,int addr);
int XM_GetVABSampleInfo(XM_VABInfo *VInfo,unsigned char *Header,unsigned char *Body,int slot);
void XM_CloseVAB2(int VabID);
void XM_PauseAll(void);
void XM_RestartAll(void);

void XM_SetSongAddress(unsigned char *Address);
int XM_GetSongSize(void);
void XM_FreeAllSongIDs(void);
void XM_FreeSongID(void);
void XM_SetSpeed(int Song_ID,unsigned short Speed);
void XM_SetBPM(int Song_ID,unsigned short BPM);

void XM_SetMono(void);
void XM_SetStereo(void);
void XM_FreeAllFileHeaderIDs(void);
void XM_FreeFileHeaderID(void);
void XM_SetFileHeaderAddress(unsigned char *Address);
int XM_GetFileHeaderSize(void);

#ifdef XMPLAY_VARIANT_SBSPSS
void XM_Update2(int speed);
void SetTranspose(int a);
#endif

#if defined(XMPLAY_VARIANT_REDRIVER2) && defined(XMPLAY_ENABLE_FIXES)
void SilenceXM(int Song_ID);
#endif