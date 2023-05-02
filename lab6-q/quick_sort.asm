global quick_sort

quick_sort:

INIT_QUICKSORT:
    mov     r9,     0
    mov     r10,    rsi
    dec     r10

QUICKSORT:
    push    rbp
    mov     rbp,    rsp

    cmp     r9,     r10
    jge     END_QUICKSORT

    mov     r11,    r9
    mov     r12,    r10
    mov     r13,    qword [rdi + r9*8]

WHILE_START:
    cmp     r11,    r12
    je      END_WHILE


INNERWHILE_1:
    mov     r15,    qword [rdi + r12*8]

    cmp     r15,    r13
    jle     END_INNERWHILE_1

    cmp     r11,    r12
    jge     END_INNERWHILE_1

    dec     r12
    jmp     INNERWHILE_1

END_INNERWHILE_1:

INNERWHILE_2:
    mov     r14,    qword [rdi + r11*8]

    cmp     r14,    r13
    jg      END_INNERWHILE_2

    cmp     r11,    r12
    jge     END_INNERWHILE_2

    inc     r11
    jmp     INNERWHILE_2

END_INNERWHILE_2:

IF:
    cmp     r11,    r12
    jge     END_IF

    mov     qword [rdi + r11*8],     r15
    mov     qword [rdi + r12*8],     r14

END_IF:
    jmp     WHILE_START

END_WHILE:

    mov     qword [rdi + r9*8],      r14
    mov     qword [rdi + r11*8],     r13

    sub     rsp,    32
    mov     qword [rsp + 24],       r9
    mov     qword [rsp + 16],       r10
    mov     qword [rsp + 8],        r11

    mov     r10,    r11
    dec     r10
    call    QUICKSORT
    
    mov     r9,     qword [rsp + 24]
    mov     r10,    qword [rsp + 16]
    mov     r11,    qword [rsp + 8]

    mov     r9,     r11
    inc     r9
    call    QUICKSORT

    add     rsp,    32
    jmp     END_QUICKSORT

END_QUICKSORT:
    leave
    ret