/**
 * @file entry_export.h
 * @brief The fields and structures exported by the entry shell.
 *
 * @author Chen Zhenshuo (chenzs108@outlook.com)
 * @version 1.0
 * @date 2020-01-15
 * @par GitHub
 * https://github.com/czs108
 *
 * @warning
 * All exported data fields are just lables in the `.asm` shell file,
 * they need to be relocated by `&` operator.
 */

#pragma once

#include "../section.h"

#include <windows.h>


//! The maximum number of encrypted sections supported by the program.
#define MAX_ENCRY_SECTION_COUNT 0x40


/**
 * @brief The encryption information of a segment of the shell.
 */
typedef struct _SEG_ENCRY_INFO {
    //! The offset, relative to the shell.
    DWORD seg_offset;

    //! The size.
    DWORD seg_size;
	QWORD seg_key;

} SEG_ENCRY_INFO;


/**
 * @brief The original PE information.
 */
typedef struct _ORIGIN_PE_INFO {
    //! The offset, relative to the shell.
    DWORD entry_point;

    //! The offset of the original import table, relative to the load segment.
    DWORD imp_table_offset;

    //! The relative virtual address of the relocation table.
    DWORD reloc_table_rva;

    //! The image base.
    VOID* image_base;

    //! The encryption information of sections, up to 0x40 sections and a blank structure.
    ENCRY_INFO section_encry_info[MAX_ENCRY_SECTION_COUNT + 1];

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

extern IMAGE_TLS_DIRECTORY tls_table;