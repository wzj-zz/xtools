;====================================================================================================
;;x64_jmp target
;;x86_jmp target
;;x64_jmp_rax target
;;x64_call target
;;x86_call target
;;x64_cmp reg, imm
;;x86_cmp reg, imm
;;eq_brk
;;x64_reg_save reg (except r10), address
;;x64_hk_op args_address
;;x64_hk_ed org_ins
;;x64_hk_ret HookEntry, org_ins
;;x64_ps_brk PsGetCurrentProcess, KPROCESS
;;x64_ps_tag_brk PsGetCurrentProcess, KPROCESS, tag_address, tag_value
;;x64_ps_ret_brk PsGetCurrentProcess, KPROCESS, return_value
;;x64_reg_range_brk reg_count, (reg, range_op, range_ed)
;;x64_ps_reg_range_brk PsGetCurrentProcess, KPROCESS, reg_count, (reg, range_op, range_ed)
;====================================================================================================

; %1 target
%macro x64_jmp 1
		bits 64
		push rax
		mov dword [rsp], %1 & 0xffffffff
		mov dword [rsp+4], (%1 >> 32) & 0xffffffff
		ret
%endmacro

; %1 target
%macro x86_jmp 1
		bits 32
		push %1
		ret
%endmacro

; %1 target
%macro x64_jmp_rax 1
		bits 64
		mov rax, %1
		jmp rax
%endmacro

; %1 target
%macro x64_call 1
		bits 64
		mov rax, %1
		call rax
%endmacro

; %1 target
%macro x86_call 1
		bits 32
		mov eax, %1
		call eax
%endmacro

; %1 reg
; %2 imm
%macro x64_cmp 2
		bits 64
		mov dword [rsp-8], %2 & 0xffffffff
		mov dword [rsp-4], (%2 >> 32) & 0xffffffff
		cmp %1, [rsp-8]
%endmacro

; %1 reg
; %2 imm
%macro x86_cmp 2
		bits 32
		cmp %1, %2
%endmacro

%macro eq_brk 0
		jne %%eq_brk_false
		db 0xcc
%%eq_brk_false:
%endmacro

; %1 reg (except r10)
; %2 address
%macro x64_reg_save 2
		bits 64
		push r10
		mov r10, %2
		mov [r10], %1
		pop r10
%endmacro

; %1 args address
%macro x64_hk_op 1
		bits 64
		push r10
		mov r10, %1
		mov [r10], rcx
		mov [r10+0x8], rdx
		mov [r10+0x10], r8
		mov [r10+0x18], r9
		pop r10
%endmacro

; %* original instructions
%macro x64_hk_ed 1-*
		bits 64
		db %{1:-1}
%endmacro

; %1 HookEntry
; %* original instructions
%macro x64_hk_ret 1-*
		bits 64
%%org_ins:
		db %{2:-1}
		org_ins_len equ $-%%org_ins
		x64_jmp %1+org_ins_len
%endmacro

; %1 PsGetCurrentThread	PsGetCurrentThreadId	PsGetCurrentProcess	PsGetCurrentProcessId
; %2 KTHREAD			tid						KPROCESS			pid
%macro x64_ps_brk 2
		bits 64
		push rax
		x64_call %1
		x64_cmp rax, %2
		eq_brk
		pop rax
%endmacro

; ExAllocatePoolWithTag ExAllocatePool2
; %1 PsGetCurrentProcess	PsGetCurrentProcessId
; %2 KPROCESS				pid
; %3 tag address
; %4 tag value
%macro x64_ps_tag_brk 4
		bits 64
		push rcx
		push r10
		push rax
		x64_call %1
		x64_cmp rax, %2
		jne %%x64_ps_tag_brk_false
		mov rax, %3
		mov eax, [rax]
		mov r10d, %4
		

		mov cl, -4
%%loop_0:		
		test r10b, r10b
		je %%loop_next
		cmp al, r10b
		jne %%x64_ps_tag_brk_false
%%loop_next:
		ror eax, 8
		ror r10d, 8
		
		inc cl
		test cl, cl
		jne %%loop_0
		
		db 0xcc
%%x64_ps_tag_brk_false:
		pop rax
		pop r10
		pop rcx
%endmacro

; %1 PsGetCurrentProcess	PsGetCurrentProcessId
; %2 KPROCESS				pid
; %3 return value
%macro x64_ps_ret_brk 3
		bits 64
		push rax
		x64_call %1
		x64_cmp rax, %2
		jne %%x64_ps_ret_brk_false
		mov rax, [rsp]
		x64_cmp rax, %3
		jne %%x64_ps_ret_brk_false
		db 0xcc
%%x64_ps_ret_brk_false:
		pop rax
%endmacro

; %1 reg count
; %* (reg, range_op, range_ed)
%macro x64_reg_range_brk 1-*
		bits 64
		%if %1==1
			x64_cmp %2, %3
			jb %%x64_reg_range_brk_false
			x64_cmp %2, %4
			ja %%x64_reg_range_brk_false
		%elif %1==2
			x64_cmp %2, %3
			jb %%x64_reg_range_brk_false
			x64_cmp %2, %4
			ja %%x64_reg_range_brk_false
			x64_cmp %5, %6
			jb %%x64_reg_range_brk_false
			x64_cmp %5, %7
			ja %%x64_reg_range_brk_false
		%elif %1==3
			x64_cmp %2, %3
			jb %%x64_reg_range_brk_false
			x64_cmp %2, %4
			ja %%x64_reg_range_brk_false
			x64_cmp %5, %6
			jb %%x64_reg_range_brk_false
			x64_cmp %5, %7
			ja %%x64_reg_range_brk_false
			x64_cmp %8, %9
			jb %%x64_reg_range_brk_false
			x64_cmp %8, %10
			ja %%x64_reg_range_brk_false
		%elif %1==4
			x64_cmp %2, %3
			jb %%x64_reg_range_brk_false
			x64_cmp %2, %4
			ja %%x64_reg_range_brk_false
			x64_cmp %5, %6
			jb %%x64_reg_range_brk_false
			x64_cmp %5, %7
			ja %%x64_reg_range_brk_false
			x64_cmp %8, %9
			jb %%x64_reg_range_brk_false
			x64_cmp %8, %10
			ja %%x64_reg_range_brk_false
			x64_cmp %11, %12
			jb %%x64_reg_range_brk_false
			x64_cmp %11, %13
			ja %%x64_reg_range_brk_false
		%endif
		db 0xcc
%%x64_reg_range_brk_false:
%endmacro

; %1 PsGetCurrentProcess
; %2 KPROCESS
; %3 reg count
; %* (reg, range_op, range_ed)
%macro x64_ps_reg_range_brk 1-*
		bits 64
		push rax
		x64_call %1
		x64_cmp rax, %2
		jne %%x64_ps_reg_range_brk_false
		mov rax, [rsp]
		
		%if %3==1
			x64_cmp %4, %5
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %4, %6
			ja %%x64_ps_reg_range_brk_false
		%elif %3==2
			x64_cmp %4, %5
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %4, %6
			ja %%x64_ps_reg_range_brk_false
			x64_cmp %7, %8
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %7, %9
			ja %%x64_ps_reg_range_brk_false
		%elif %3==3
			x64_cmp %4, %5
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %4, %6
			ja %%x64_ps_reg_range_brk_false
			x64_cmp %7, %8
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %7, %9
			ja %%x64_ps_reg_range_brk_false
			x64_cmp %10, %11
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %10, %12
			ja %%x64_ps_reg_range_brk_false
		%elif %3==4
			x64_cmp %4, %5
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %4, %6
			ja %%x64_ps_reg_range_brk_false
			x64_cmp %7, %8
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %7, %9
			ja %%x64_ps_reg_range_brk_false
			x64_cmp %10, %11
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %10, %12
			ja %%x64_ps_reg_range_brk_false
			x64_cmp %13, %14
			jb %%x64_ps_reg_range_brk_false
			x64_cmp %13, %15
			ja %%x64_ps_reg_range_brk_false
		%endif
		db 0xcc
%%x64_ps_reg_range_brk_false:
		pop rax
%endmacro

;====================================================================================================

