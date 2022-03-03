
include shell.inc 


; RC4 helpers

RC4Decrypt proto key: qword, keylen: qword, data: qword, datalen: qword

RC4InitState proto S: qword, key: qword, keylen: qword 

RC4GenerateRandomByte proto S: qword, i_ref: qword, j_ref: qword

; RC4 helpers 

GetSectionHeader proto base: qword 

SetSectionProtections proto _VirtualProtect: qword, base: qword, new_protection_arr: qword, old_protection_arr: qword

MAX_ENCRY_SECTION_COUNT equ 40h

public shell_begin_lbl

public imp_table_begin_lbl

public imp_table_end_lbl

public boot_seg_begin_lbl

public boot_seg_end_lbl

public load_seg_begin_lbl

public load_seg_end_lbl

public load_seg_encry_info

public orig_pe_info

public tls_table

SEG_ENCRY_INFO	struct 
	seg_offset	dword ?
	seg_size	dword ?
	seg_key		qword ?
SEG_ENCRY_INFO	ends 

SECTION_ENCRY_INFO struct 
	sec_rva 	dword ?
	sec_size	dword ?
	sec_key 	qword ?
SECTION_ENCRY_INFO ends 

ORIGIN_PE_INFO struct 
	entry_point	dword ?
	imp_table_offset dword ?
	reloc_table_rva dword ?
	image_base 	qword ?
	encry_info SECTION_ENCRY_INFO MAX_ENCRY_SECTION_COUNT+1 dup(<>)
ORIGIN_PE_INFO ends




.code 
shell_begin_lbl label qword

boot_seg_begin_lbl label qword

	call _boot
	
	imp_table_begin_lbl label qword
	
		import_table IMAGE_IMPORT_DESCRIPTOR <<first_thunk - imp_table_begin_lbl>, 0, 0, dll_name - \
					 imp_table_begin_lbl, first_thunk - imp_table_begin_lbl>
					 IMAGE_IMPORT_DESCRIPTOR <<0>, 0, 0, 0, 0>
					 
		first_thunk  IMAGE_THUNK_DATA64 <<first_func_name - imp_table_begin_lbl>>
		second_thunk IMAGE_THUNK_DATA64 <<second_func_name - imp_table_begin_lbl>>
		third_thunk  IMAGE_THUNK_DATA64 <<third_func_name - imp_table_begin_lbl>>
					 IMAGE_THUNK_DATA64 <<0>>
		
		dll_name db 'Kernel32.dll', 0
		first_func_name  dw 0
						 db 'GetProcAddress', 0
		second_func_name dw 0 
						 db 'GetModuleHandleA', 0
		third_func_name  dw 0
						 db 'LoadLibraryA', 0
						 
	imp_table_end_lbl label qword 
	
	load_seg_encry_info SEG_ENCRY_INFO <>
	
	tls_table	IMAGE_TLS_DIRECTORY32 <> 
	
	str_VirtualProtect db 'VirtualProtect',0
	
	VirtualProtect dq 0
	
	str_FlushInstructionCache db 'FlushInstructionCache',0
	
	FlushInstructionCache dq 0 
	
	module_base dq 0 
	
_boot:
	pop rbp 
	sub rbp, imp_table_begin_lbl - boot_seg_begin_lbl
	
	lea rsi, [rbp + dll_name - boot_seg_begin_lbl]
	mov rcx, rsi
	call qword ptr [rbp + second_thunk - boot_seg_begin_lbl]
	mov rcx, rax 
	lea rdx, [rbp + str_VirtualProtect - boot_seg_begin_lbl]
	call qword ptr [rbp + first_thunk - boot_seg_begin_lbl] 
	mov [rbp + VirtualProtect - boot_seg_begin_lbl], rax 
	
	mov rcx, rsi 
	call qword ptr [rbp + second_thunk - boot_seg_begin_lbl] 
	mov rcx, rax 
	lea rdx, [rbp + str_FlushInstructionCache - boot_seg_begin_lbl]
	call qword ptr [rbp + first_thunk - boot_seg_begin_lbl]
	mov [rbp + FlushInstructionCache - boot_seg_begin_lbl], rax 
	
	xor rcx, rcx 
	call qword ptr [rbp + second_thunk - boot_seg_begin_lbl]
	mov [rbp + module_base - boot_seg_begin_lbl], rax 
	
	lea rcx, [rbp + load_seg_encry_info - boot_seg_begin_lbl] 
	mov ebx, [rcx + 4] ;seg_size 
	mov eax, ebx
	cdqe 
	mov rbx, rax 
	push rbx 
	mov ebx, [rcx] ;seg_offset 
	mov eax, ebx 
	cdqe 
	mov rbx, rax 
	add rbx, rbp 
	push rbx 
	push 8h
	lea rbx, [rcx + 8] ;seg_key 
	push rbx 
	call RC4Decrypt
	
	mov rcx, -1 
	xor rdx, rdx 
	xor r8, r8 
	call qword ptr [rbp + FlushInstructionCache - boot_seg_begin_lbl] 
	push rbp 

boot_seg_end_lbl label qword 

load_seg_begin_lbl label qword 
	
	call _load	
_load:
	pop rbp 
	sub rbp, _load - load_seg_begin_lbl
	pop rbx 
	mov rcx, MAX_ENCRY_SECTION_COUNT
	mov eax, PAGE_EXECUTE_READWRITE
	lea rdi, [rbp + sect_protections - load_seg_begin_lbl]
	cld
	rep stosd 
	
	lea rax, [rbp + sect_protections - load_seg_begin_lbl]
	push rax
	push rax 
	push qword ptr [rbx + module_base - boot_seg_begin_lbl]
	push qword ptr [rbx + VirtualProtect - boot_seg_begin_lbl]
	call SetSectionProtections
	
	lea rdx, [rbp + orig_pe_info - load_seg_begin_lbl]
	lea rdx, [rdx + 14h] ;encry_info 
	mov eax, [rdx] ;sec_rva 
	decrypt_sections: 
	cdqe 
	mov rcx, [rbx + module_base - boot_seg_begin_lbl] 
	add rcx, rax 
	mov eax, [rdx + 4h] ;sec_size
	cdqe 
	push rax 
	push rcx 
	push 8h 
	lea rcx, [rdx + 8h] ;sec_key 
	push rcx 
	call RC4Decrypt
	add edx, sizeof(SECTION_ENCRY_INFO)
	mov eax, [rdx] ;sec_rva 
	test eax, eax 
	jnz decrypt_sections
	
	lea rdx, [rbp + orig_pe_info - load_seg_begin_lbl]
	mov eax, [rdx + 4h] ;imp_table_offset 
	cdqe 
	add rax, rbp 
	mov rdx, rax 
	mov eax, [rdx] 
	test eax, eax 
	jz imports_done
	
resolve_imports:
	cdqe 
	mov r8, [rbx + module_base - boot_seg_begin_lbl] 
	add r8, rax 
	add rdx, sizeof(DWORD) + sizeof(BYTE)
	mov rcx, rdx 
	call qword ptr [rbx + second_thunk - boot_seg_begin_lbl]
	test rax, rax
	jnz skip_load
	call qword ptr [rbx + third_thunk - boot_seg_begin_lbl] 
	
skip_load:
	mov r9, rax 
	movzx rcx, byte ptr [rdx - sizeof(BYTE)]
	add rdx, rcx 
	mov ecx, [rdx] 
	add rdx, sizeof(DWORD)
	
get_functions:
	test ecx, ecx 
	jz continue_imports
	push rcx 
	movzx rcx, byte ptr [rdx]
	add rdx, sizeof(BYTE)
	test rcx, rcx 
	jz ordinal 
	mov rax, rdx 
	add rdx, rcx 
	push rdx 
	mov rdx, rax 
	jmp get_address 
	
ordinal:
	add rdx, sizeof(DWORD)
	push rdx 
	mov eax, [rdx - sizeof(DWORD)]
	cdqe 
	mov rdx, rax 
	
get_address:
	mov rcx, r9 
	call qword ptr [rbx + first_thunk - boot_seg_begin_lbl]
	mov [r8], rax 
	add r8, sizeof(QWORD)
	pop rdx 
	pop rcx
	dec ecx 
	jmp get_functions 
	
continue_imports:
	mov eax, [rdx] 
	jnz resolve_imports
	
imports_done:
	lea r8, [rbp + orig_pe_info - load_seg_begin_lbl]
	mov r8, [r8 + 0ch] ;image_base 
	mov r9, [rbx + module_base - boot_seg_begin_lbl]
	cmp r8, r9 
	jz reloc_done 
	lea rdx, [rbp + orig_pe_info - load_seg_begin_lbl]
	mov eax, [rdx + 8h] ;reloc_table_rva
	cdqe 
	mov rdx, rax 
	test rdx, rdx 
	jz reloc_done
	xor rcx, rcx 
	xor r10, r10 
	add rdx, r9 
	mov eax, [rdx] ;VirtualAddress 
	
get_reloc:
	test eax, eax 
	jz reloc_done 
	cdqe 
	add rax, r9 
	mov ecx, [rdx + 4h] ;SizeOfBlock 
	sub ecx, sizeof(IMAGE_BASE_RELOCATION)
	shr ecx, 1 
	add rdx, sizeof(IMAGE_BASE_RELOCATION)
	
do_reloc:
	test ecx, ecx 
	jz continue_get_reloc
	mov r10w, [rdx] 
	and r10w, 0F000h
	shr r10w, 0ch 
	cmp r10w, IMAGE_REL_BASED_HIGHLOW 
	jz continue_do_reloc
	mov r10w, [rdx]
	and r10w, 0FFFh 
	add rax, r10 
	mov r11, [rax]
	sub r11, r8 
	add r11, r9 
	mov [rax], r11	
	
continue_do_reloc:
	add rdx, sizeof(WORD)
	dec ecx 
	jmp do_reloc

continue_get_reloc:
	mov eax, [rdx]
	jmp get_reloc
	
reloc_done:	

	lea rax, [rbp + sect_protections - load_seg_begin_lbl]
	push rax
	push rax 
	push qword ptr [rbx + module_base - boot_seg_begin_lbl]
	push qword ptr [rbx + VirtualProtect - boot_seg_begin_lbl]
	call SetSectionProtections
	
	mov rcx, -1
	xor rdx, rdx 
	xor r8, r8 
	call qword ptr [rbx + FlushInstructionCache - boot_seg_begin_lbl] 
	
	lea rax, [rbp + orig_pe_info - load_seg_begin_lbl]
	mov eax, [rax] ;entry_point 
	cdqe 
	add rax, qword ptr [rbx + module_base - boot_seg_begin_lbl]
	push rax 
	ret 
	sect_protections dd MAX_ENCRY_SECTION_COUNT dup(?)
	orig_pe_info ORIGIN_PE_INFO <>
	

load_seg_end_lbl label qword 
	

RC4Decrypt PROC USES rax rbx rcx rdx r8 r9, key: qword, keylen: qword, data: qword, datalen: qword
	push rbp 
	mov rbp, rsp 
	sub rsp, 108h 
	lea r8, [rbp - 108h]
	push r8
	push key 
	push keylen
	call RC4InitState 
	xor rbx, rbx 
	mov [rbp - 8h], ebx 
	mov [rbp - 4h], ebx 
	lea rcx, [rbp - 8h]
	lea rdx, [rbp - 4h] 
	decrypt_loop:
	mov rdi, data 
	add rdi, r9
	mov bl, [rdi]
	push rdx 
	push rcx 
	push r8
	call RC4GenerateRandomByte
	xor bl, al 
	mov [rdi], bl 
	inc r9 
	cmp r9, datalen 
	jb decrypt_loop

	mov rsp, rbp 
	pop rbp 
	ret 20h

RC4Decrypt ENDP 

RC4InitState PROC USES rax rbx rcx rdx r8, S: qword, key: qword, keylen: qword 

	xor rcx, rcx
	init_first_loop:
	mov rax, S
	add rax, rcx 
	mov [rax], cl 
	inc rcx 
	cmp cl, 0ffh 
	jb init_first_loop 
	
	xor rcx, rcx 
	xor rdx, rdx 
	init_second_loop:
	mov rax, S
	add rax, rcx 
	mov bl, [rax]
	push rbx 
	add bl, dl 
	mov rax, rcx 
	idiv keylen 
	mov rax, key 
	add rax, rdx 
	add bl, [rax] 
	movzx rdx, bl 
	mov rax, S
	add rax, rcx 
	mov r8, S
	add r8, rdx 
	mov bl, [r8]
	mov [rax], bl 
	pop rbx
	mov [r8], bl 
	inc rcx 
	cmp cl, 0ffh 
	jb init_second_loop   
	ret 18h 
	
RC4InitState ENDP 

RC4GenerateRandomByte PROC USES rbx rcx rdx r8, S: qword, i_ref: qword, j_ref: qword
	
	mov r9, i_ref
	mov ecx, [r9] 
	mov r10, j_ref
	mov edx, [r10] 
	inc cl 
	mov [r9], ecx 
	mov eax, edx 
	cdqe 
	mov rdx, rax 
	mov rax, S
	add rax, rdx 
	add dl, [rax] 
	mov [r10], edx 
	mov eax, ecx 
	cdqe 
	mov rcx, rax 
	mov rax, S
	add rax, rcx 
	mov bl, [rax]
	push rbx 
	mov r8, S
	add r8, rdx 
	mov bl, [r8]
	mov cl, dl 
	mov [rax], bl 
	pop rbx
	mov [r8], bl 
	add bl, cl 
	movzx rbx, bl 
	mov rax, S
	add rax, rbx 
	mov al, [rax]
	ret 18h 
	
RC4GenerateRandomByte ENDP 

GetSectionHeader PROC USES rax rbx rcx,  base: qword 
 
	mov rax, base 
	mov ebx, [rax + 3ch] 
	mov eax, ebx 
	cdqe 
	mov rbx, rax 
	mov rax, base 
	add rax, rbx 
	xor rcx, rcx 
	mov cx, [rax + 6h] ;FileHeader.NumberOfSections
	xor rbx, rbx 
	mov bx, [rax + 14h] ;FileHeader.SizeOfOptionalHeader
	add rax, 1Bh ; sizeof(FileHeader) + sizeof(DWORD)
	add rax, rbx 
	ret 8h 
	
GetSectionHeader ENDP 

SetSectionProtections PROC USES rax rbx rcx rdx r8 r9, _VirtualProtect: qword, base: qword, new_protection_arr: qword, old_protection_arr: qword

	push base 
	call GetSectionHeader
	mov rbx, rax 
	mov rsi, new_protection_arr
	mov rdi, old_protection_arr
	xor rdx, rdx 
	set_protection_loop:
	push rcx 
	push rdx 
	lea rax, [rsi + 4h * rdx] 
	mov r9, rax 
	mov eax, [rdi + 4h * rdx] 
	mov r8d, eax
	mov edx, [ebx + 8h] ; IMAGE_SECTION_HEADER.Misc.VirtualSize 
	mov rcx, base 
	mov eax, [ebx + 0ch] ; IMAGE_SECTION_HEADER.Misc.VirtualAddress
	cdqe 
	add rcx, rax
	call _VirtualProtect 
	add rbx, 28h
	pop rdx 
	pop rcx 
	inc rdx 
	cmp rdx, rcx 
	jb set_protection_loop	
	
	ret 20h

SetSectionProtections ENDP 

end 