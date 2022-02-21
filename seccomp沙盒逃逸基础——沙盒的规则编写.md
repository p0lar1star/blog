# seccomp沙盒逃逸基础——沙盒的规则编写

# 引入：

> **安全计算模式** **seccomp**（Secure Computing Mode）是自 Linux 2.6.10 之后引入到 kernel 的特性。一切都在内核中完成，不需要额外的上下文切换，所以不会造成性能问题。目前 在 **Docker** 和 **Chrome** 中**广泛使用**。**使用 seccomp**，**可以定义系统调用白名单**和**黑名单**，可以 定义出现非法系统调用时候的动作，比如结束进程或者使进程调用失败。
>
> seccomp机制**用于限制应用程序可以使用的系统调用**，**增加系统的安全性**。
>
> 在/proc/${pid}/status文件中的**Seccomp字段**可以**看到进程的Seccomp。**

# 简介：

**seccomp** 是 Linux 内核提供的一种应用程序沙箱机制，seccomp 通过**只允许应用程序调用** **exit(), sigreturn(), read() 和 write()** **四种系统调用**来达到沙箱的效果。**如果**应用程序**调用了**除了这**四种之外的系统调用**， **kernel** 会向进程**发送 SIGKILL 信号。**

## prctl 函数

prctl就是在c程序中可以使用BPF过滤规则操作进程的一个函数调用。函数原型如下：

```
#include <sys/prctl.h>
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
```

option有很多，CTF中一般只关注两种option：PR_SET_NO_NEW_PRIVS(38)和PR_SET_SECCOMP(22)：

### 1.若option为PR_SET_NO_NEW_PRIVS(38)：

若**第二个参数arg2设置为1**，那么程序线程将**不能通过执行execve系统调用来获得提权**，该选项只对**execve这个系统调用有效**。意思就是若你使用syscall(59,'/bin/sh',null,null)或system("/bin/sh")（内部还是系统调用execve）获得的线程shell，用户组依然是之前的用户组，且**不能获得更高权限**。

也就是说：

**prctl(38, 1LL, 0LL, 0LL, 0LL)**表示**禁用系统调用**，也就是**system**和**onegadget**都没了，还会教子进程也这么干，很坏；

### 2.若option为PR_SET_SECCOMP(22)：

option为22时，表示**可以设置沙箱规则**，也就是可以自定义函数的系统调用是被允许还是禁止。

如果arg2为SECCOMP_MODE_STRICT(1),则只允许调用read,write,_exit(not exit_group),sigreturn这几个syscall。

在ida中可以看到prctl(22, 1LL);

![image-20210424141833001](https://i.loli.net/2021/04/24/qNlvMbm9QCzxrdj.png)

如果arg2为SECCOMP_MODE_FILTER(2),则为过滤模式,其中对syscall的限制通过参数3的结构体，来自定义过滤规则，此时函数原型如下。

```
prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
```

&prog形式如下：

```
struct sock_fprog {
    unsigned short        len;    /* 指令个数 */
    struct sock_filter *filter; /*指向包含struct sock_filter的结构体数组指针*/
};
```

filter是一个结构体数组，里面的元素就是各种规则（可以认为是指令），下面就是一个过滤execve系统调用的过滤规则，与BPF (Berkeley Packets Filter)相关，暂时不深究：

```
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),           //将帧的偏移0处，取4个字节数据，也就是系统调用号的值载入累加器
    BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),           //当A == 59时，顺序执行下一条规则（返回KILL），否则跳过下一条规则（也就是返回ALLOW），这里的59就是x64的execve系统调用号
    BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),   //返回KILL
    BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),  //返回ALLOW
};
```

使用ptrcl禁用execve系统调用的实例：

```
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdlib.h>
int main()
{
	struct sock_filter filter[] = {                
    	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
    	BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
    	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
    	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {                                   
    	len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),//规则条数
    	filter = filter,                                         //结构体数组指针
	};
    	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);             //必要的，设置NO_NEW_PRIVS
    	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
    	write(0,"test\n",5);
    	system("/bin/sh");
    	return 0;
}
```

## 基于BPF(伯克利分组过滤器)的seccomp库函数

基于prctl系统调用的机制不够灵活，这个库可以提供一些函数实现prctl类似的效果，库中封装了一些函数，可以不用了解BPF规则而实现过滤。

但是在c程序中使用它，需要装一些库文件

```
sudo apt install libseccomp-dev libseccomp2 seccomp
```

**scmp_filter_ctx**是过滤器的结构体类型

**seccomp_init**对结构体进行初始化，**若参数为SCMP_ACT_ALLOW，则没有匹配到规则的系统调用将被默认允许，过滤为黑名单模式；若为SCMP_ACT_KILL，则为白名单模式，即没有匹配到规则的系统调用都会杀死进程，默认不允许所有的syscall。**

**seccomp_rule_add**是添加一条规则，其函数原型如下：

```
int seccomp_rule_add(scmp_filter_ctx ctx, uint32_t action, int syscall, unsigned int arg_cnt, ...);
```

arg_cnt表明是否需要对对应系统调用的参数做出限制以及指示做出限制的个数，如果仅仅需要允许或者禁止所有某个系统调用，arg_cnt直接传入0即可

下面举两个例子：

**seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);即禁用execve，不管其参数如何。**

**seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2,  SCMP_A0(SCMP_CMP_EQ, 1), SCMP_A1(SCMP_CMP_EQ, 2));即当调用dup2函数时，只有前两个参数为1和2时，才允许调用**。因此，dup2(1, 2);被允许，dup2(2, 42);被阻止。

使用该库的函数实现禁用execve系统调用的实例

```
//gcc seccomptest.c -o seccomptest -lseccomp
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
 
int main(void){
    scmp_filter_ctx ctx;// Init the filter
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_load(ctx);
 
    char * str = "/bin/sh";
    write(1,"i will give you a shell\n",24);
    syscall(59,str,NULL,NULL);//execve
    return 0;
}
```

另一个实例：

```
#include <stdio.h>   /* printf */
#include <unistd.h>  /* dup2: just for test */
#include <seccomp.h> /* libseccomp */
 
int main() {
  printf("step 1: unrestricted\n");
 
  // Init the filter
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill 未在白名单的系统调用都被杀死
 
  // setup basic whitelist 设置白名单，以下系统调用被允许
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  
  // setup our rule 设置特定参数的系统调用白名单，dup2(1，2)被允许
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2, 
                        SCMP_A0(SCMP_CMP_EQ, 1),
                        SCMP_A1(SCMP_CMP_EQ, 2));
 
  // build and load the filter
  seccomp_load(ctx);
  printf("step 2: only 'rerw' and dup2(1, 2) syscalls\n");
  
  // Redirect stderr to stdout
  dup2(1, 2);
  printf("step 3: stderr redirected to stdout\n");
 
  // Duplicate stderr to arbitrary fd
  dup2(2, 42);
  printf("step 4: !! YOU SHOULD NOT SEE ME !!\n");
 
  // Success (well, not so in this case...)
  return 0; 
}
```

再来一个例子：

```
#include<stdio.h>
#include<unistd.h>
#include<sys/syscall.h>
#include<sys/prctl.h>
#include<linux/seccomp.h>
#include<seccomp.h>

int main()
{
    char *argv[]={"/bin/cat", "flag", NULL};
    char *env[]={NULL};
    char cmd[20] = "/bin/cat";

    scmp_filter_ctx ctx;// Init the filter
    ctx = seccomp_init(SCMP_ACT_ALLOW); // default action: Allow
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);//在禁止write时，SCMP_ACT_KILL也默认不允许所有的syscall
    seccomp_load(ctx);

    syscall(0x3b, cmd, argv, env);
    return 0;
}
```

结果：

```
➜  seccomp-escape ./syscall
[1]    2730 invalid system call (core dumped)  ./syscall
```

## 子进程seccomp

另外，seccomp的沙箱同样适用于子进程，即通过fork也不能逃出sandbox。

```
#include<stdio.h>
#include<unistd.h>
#include<sys/syscall.h>
#include<sys/prctl.h>
#include<linux/seccomp.h>
#include<seccomp.h>
#include<sys/types.h>
#include<sys/wait.h>

int main()
{
    char *argv[]={"/bin/cat", "flag", NULL};
    char *env[]={NULL};
    char cmd[20] = "/bin/cat";

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW); // default action: Allow
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);
    seccomp_load(ctx);

    //syscall(0x3b, cmd, argv, env);

        pid_t pid;
        int rv;
    pid = fork();
    if(pid == 0){    // child process
        syscall(59, cmd, argv, env);
    }
    else
    {
        waitpid(pid, &rv, 0);
    }
    return 0;

    return 0;
}
```

结果:

```
➜  seccomp-escape ./syscall
➜  seccomp-escape
```

# 查看沙箱规则

```
seccomp-tools dump ./pwn1
```

![image-20210424141220348](https://i.loli.net/2021/04/24/w3rPJYLlpK4gmTD.png)

# 编写沙箱规则的shellcode

使用seccomp-tools生成规则，一条规则是8个字节

```
#cat 1.asm
A = sys_number
A == 257? e0:next
A == 1? ok:next
return ALLOW
e0:
return ERRNO(0)
ok:
return ALLOW
```

规则如下：

```
#seccomp-tools asm 1.asm -f raw |seccomp-tools disasm -
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x02 0x00 0x00000101  if (A == openat) goto 0004
 0002: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0005
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

生成16进制字符串

```
#seccomp-tools asm 1.asm
"\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x02\x00\x01\x01\x00\x00\x15\x00\x02\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"
```

