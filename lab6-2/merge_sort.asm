global merge_sort

merge_sort:
INIT_MERGESORT:
    mov     r8,     rdi
    mov     r9,     0
    mov     r10,    rsi


MERGESORT: 
    push    rbp
    mov     rbp,    rsp

    cmp     r9,     r10
    jge     END_MERGESORT

    mov     r11,    r10
    sub     r11,    r9
    shr     r11,    1
    add     r11,    r9

    sub     rsp,    8
    mov     qword [rsp],    r10
    mov     r10,    r11
    jmp     MERGESORT

    pop     r10
    add     rsp,    8

    sub     rsp,    8
    mov     qword [rsp],    r9
    mov     r9,     r11
    inc     r9
    jmp     MERGESORT

    pop     r9
    add     rsp,    8

    jmp     MERGE

END_MERGESORT:
    leave


MERGE:
    push    rbp
    mov     rbp,    rsp

    mov     r15,   r11
    sub     r15,   r9
    inc     r15

    mov     rbx,   r10
    sub     rbx,   r11

    sub     rsp,    r15

    mov     rcx, r15
    mov     rsi, rbp
    mov     rdi, r8
    add     rdi, r9
    rep     movsb
    
    sub     rsp,    rbx

    mov     rcx, rbx
    mov     rsi, rbp
    mov     rdi, r8
    add     rdi, r11
    inc     rdi
    rep     movsb

    mov     r12, 0
    mov     r13, 0
    mov     r14, r9


WHILE_CMP_BEFORE_LOOP_1:
    cmp     r12, r15
    jge     END_WHILE_1

    cmp     r11, rbx
    jge     END_WHILE_1

WHILE_LOOP_1:
    mov     rax, qword [rbp + r12 * 8]
    mov     rcx, rbp
    add     rcx, r15
    mov     rdx, qword [rcx + r13 * 8]

    cmp     rax, rdx
    jle     IF_BLOCK_1

ELSE_BLOCK_1:
    mov     qword [r8 + r14 * 8], rdx
    inc     r13
    jmp     CONTINUE_1

IF_BLOCK_1:
    mov     qword [r8 + r14 * 8], rax
    inc     r12
    jmp     CONTINUE_1

CONTINUE_1:
    inc     r14
    jmp     WHILE_CMP_BEFORE_LOOP_1

END_WHILE_1:


WHILE_CMP_BEFORE_LOOP_2:
    cmp     r12, r15
    jge     END_WHILE_2

WHILE_LOOP_2:
    mov     qword [r8 + r14 * 8], rax
    add     r12, 1
    add     r14, 1
    jmp     WHILE_CMP_BEFORE_LOOP_2

END_WHILE_2:


WHILE_CMP_BEFORE_LOOP_3:
    cmp     r13, rbx
    jge     END_WHILE_3

WHILE_LOOP_3:
    mov     qword [r8 + r14 * 8], rdx
    add     r13, 1
    add     r14, 1
    jmp     WHILE_CMP_BEFORE_LOOP_3

END_WHILE_3:
    sub     rsp,    r15
    sub     rsp,    rbx
    leave
    jmp     MERGESORT
