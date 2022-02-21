# 在linux下编译并以qemu user模式运行mips架构的文件

打完国赛初赛，水一篇博客

## 前述

QEMU是一个处理器模拟软件，可以用来**在PC中模拟ARM、MIPS等多种架构的软硬件运行环境**。QEMU主要有两种模拟模式：

- System Mode
  System模式中，它可以虚拟多种CPU架构的虚拟计算机系统，比如可以在x86 的 Ubuntu系统中虚拟出一个MIPS架构的Debian系统。
- User Mode
  User模式中，它可以运行为其他处理器编写的应用程序，比如可以在X64 Ubuntu系统中直接运行 MIPS Linux的应用程序。

QEMU功能强大，安装起来也很简单。在Ubuntu版本，只需要一条命令就可以把QEMU（本次博客涉及的安装文件）安装好.QEMU 其他架构的软件包这里没有涉及就没安装。

## 安装qemu-user模式

```
sudo apt install qemu-user
```

## 编译与运行

安装编译器：

```
sudo apt-get update
sudo apt-get install binutils-mipsel-linux-gnu
sudo apt-get install binutils-mips-linux-gnu
sudo apt-get install gcc-mipsel-linux-gnu
sudo apt install gcc-mips-linux-gnu 
```

写一个pwn题：

```
#include<stdio.h>
#include<stdlib.h>

void backdoor(){
    system("/bin/sh");
}

int main(){
    char buf[100];
    puts("Hello! Please input what you want to input!");
    read(0, buf, 0x100);
    puts("Good Bye!");
    return 0;
}
```

编译出mips**小端**程序，注意采用静态链接，否则运行时会提醒缺少库文件，那时需要用-L参数指定运行库的位置，比较麻烦，这里采用静态链接相对简单

```
mipsel-linux-gnu-gcc -static test.c -o test-mips-little
```

![image-20210520230306697](https://i.loli.net/2021/05/20/FT9KCJ6rpjawhVc.png)

编译出mips**大端**程序，同样采用静态链接：

```
mips-linux-gnu-gcc -static test.c -o test-mips-big
```

![image-20210520230137145](https://i.loli.net/2021/05/20/UqVKHNO3e1GxZP7.png)

运行：

```
qemu-mips ./test-mips-big
```

![image-20210520230335088](https://i.loli.net/2021/05/20/KGO64IhdgVrb752.png)

```
qemu-mipsel ./test-mips-little
```

![image-20210520230526818](https://i.loli.net/2021/05/20/d7NPj2YDLfeIR18.png)

其实编译运行arm程序也类似

首先要安装 arm-gcc，在 ubuntu 里可以直接 apt 安装。

```
sudo apt install gcc-arm-linux-gnueabi
```

安装好后就可以交叉编译 arm 程序了，注意用**静态**链接。

```
arm-linux-gnueabi-gcc -static test.c -o test-arm
```

![image-20210521001949446](https://i.loli.net/2021/05/21/T53MyjbA7mlagsh.png)
