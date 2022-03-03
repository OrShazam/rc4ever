#ifndef EXPORTS_H
#define EXPORTS_H 

#include <windows.h>

#define MAX_ENCRY_SECTION_COUNT 0x40 

typedef struct _SEG_ENCRY_INFO {
	DWORD seg_offset;
	DWORD seg_size;
	QWORD seg_key;
} SEG_ENCRY_INFO;

typedef struct _ORIGIN_PE_INFO {
	DWORD entry_point;
	DWORD imp_table_offset;
	DWORD reloc_table_rva;
	PVOID image_base;
	SECTION_ENCRY_INFO encry_info[MAX_ENCRY_SECTION_COUNT + 1];
} ORIGIN_PE_INFO;

extern QWORD shell_begin_lbl;

extern QWORD imp_table_begin_lbl;

extern QWORD imp_table_end_lbl;

extern QWORD boot_seg_begin_lbl;

extern QWORD boot_seg_end_lbl;

extern QWORD load_seg_begin_lbl;

extern QWORD load_seg_end_lbl;

extern SEG_ENCRY_INFO load_seg_encry_info;

extern ORIGIN_PE_INFO orig_pe_info;

extern IMAGE_TLS_DIRECTORY32 tls_table;










#endif