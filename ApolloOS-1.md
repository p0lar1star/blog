# 预备知识

[Hello, RISC-V!](https://p0lar1s.com/index.php/archives/Hello-RISC-V.html)

# 应用程序与基本执行环境

## 内核的第一条指令

### 编写内核第一条指令

编写进入内核后的第一条指令，方便我们验证我们的内核镜像是否正确对接到 Qemu 上

```assembly
# os/src/entry.asm
    .section .text.entry
    .global _start
_start:
    li x1, 100
```

在 `main.rs` 中嵌入这段汇编代码，这样 Rust 编译器才能够注意到它，不然编译器会认为它是一个与项目无关的文件：

```rust
// os/src/main.rs
#![no_std]
#![no_main]

mod lang_item;

use core::arch::global_asm;
global_asm!(include_str!("entry.asm"));
```

### 调整内核的内存布局

由于链接器默认的内存布局并不能符合我们的要求，实现与 Qemu 的正确对接，我们可以通过 **链接脚本** (Linker Script) 调整链接器的行为，使得最终生成的可执行文件的内存布局符合我们的预期。我们修改 Cargo 的配置文件来使用我们自己的链接脚本 `os/src/linker.ld` 而非使用默认的内存布局：

```assembly
OUTPUT_ARCH(riscv)
ENTRY(_start)
BASE_ADDRESS = 0x80200000;

SECTIONS
{
    . = BASE_ADDRESS;
    skernel = .;

    stext = .;
    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4K);
    etext = .;
    srodata = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    . = ALIGN(4K);
    erodata = .;
    sdata = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4K);
    edata = .;
    .bss : {
        *(.bss.stack)
        sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    ebss = .;
    ekernel = .;

    /DISCARD/ : {
        *(.eh_frame)
    }
}
```

冒号前面表示最终生成的可执行文件的一个段的名字，**花括号内按照放置顺序描述将所有输入目标文件的哪些段放在这个段中**，每一行格式为 `<ObjectFile>(SectionName)`，表示目标文件 `ObjectFile` 的名为 `SectionName` 的段需要被放进去。我们也可以使用通配符来书写 `<ObjectFile>` 和 `<SectionName>` 分别表示可能的输入目标文件和段名。因此，最终的合并结果是，在最终可执行文件中各个常见的段 `.text, .rodata .data, .bss` 从低地址到高地址按顺序放置，每个段里面都包括了所有输入目标文件的同名段，且**每个段都有两个全局符号给出了它的开始和结束地址**（比如 `.text` 段的开始和结束地址分别是 `stext` 和 `etext` ）。

编译后得到os，这是一个elf文件

![image-20220319142241481](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041731232.png)

没有去除元数据，在加载时，内核的第一条指令还是不在0x80200000处，原因如下：

![../_images/load-into-qemu.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041731392.png)

图中，红色的区域表示内核可执行文件中的元数据，深蓝色的区域表示各个段（包括代码段和数据段），而浅蓝色区域则表示内核被执行的第一条指令，它位于深蓝色区域的开头。图示的上半部分中，我们直接将内核可执行文件 `os` 加载到 Qemu 内存的 `0x80200000` 处，由于内核可执行文件的开头是一段元数据，这会导致 Qemu 内存 `0x80200000` 处无法找到内核第一条指令，也就意味着 RustSBI 无法正常将计算机控制权转交给内核。相反，图示的下半部分中，将元数据丢弃得到的内核镜像 `os.bin` 被加载到 Qemu 之后，则可以在 `0x80200000` 处正确找到内核第一条指令。

故使用rust-objcopy去除文件头等元数据，大小显著减少，见下：

```
rust-objcopy --strip-all target/riscv64gc-unknown-none-elf/release/os -O binary target/riscv64gc-unknown-none-elf/release/os.bin
```

![image-20220319143044460](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041731417.png)

## 基于 GDB 验证启动流程

在 `os` 目录下通过以下命令启动 Qemu 并加载 RustSBI 和内核镜像：

```
qemu-system-riscv64 \
    -machine virt \
    -nographic \
    -bios ../bootloader/rustsbi-qemu.bin \
    -device loader,file=target/riscv64gc-unknown-none-elf/release/os.bin,addr=0x80200000 \
    -s -S
```

`-s` 可以使 Qemu 监听本地 TCP 端口 1234 等待 GDB 客户端连接，而 `-S` 可以使 Qemu 在收到 GDB 的请求后再开始运行。因此，Qemu 暂时没有任何输出。注意，如果不想通过 GDB 对于 Qemu 进行调试而是直接运行 Qemu 的话，则要删掉最后一行的 `-s -S` 。

打开另一个终端，启动一个 GDB 客户端连接到 Qemu ：

```
$ riscv64-unknown-elf-gdb \
    -ex 'file target/riscv64gc-unknown-none-elf/release/os' \
    -ex 'set arch riscv:rv64' \
    -ex 'target remote localhost:1234'
```

![image-20220319154350258](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041731477.png)

成功执行第一条指令

![image-20220319154452467](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041731615.png)

## 为内核支持函数调用

在 `entry.asm` 中分配启动栈空间，并在控制权被转交给 Rust 入口之前将栈指针 `sp` 设置为栈顶的位置。

```assembly
# os/src/entry.asm
    .section .text.entry
    .global _start
_start:
    la sp, boot_stack_top
    call rust_main

    # stack
    .section .bss.stack
    .global boot_stack
boot_stack:
    # 64KB
    .space 4096 * 16
    .global boot_stack_top
boot_stack_top:
```

上述代码在内核的内存布局中预留了一块大小为 4096 * 16 字节也就是 64KiB 的空间用作接下来要运行的程序的栈空间。在 RISC-V 架构上，栈是从高地址向低地址增长，因此我们用更高地址的符号 `boot_stack_top` 来标识栈顶的位置，而用更低地址的符号 `boot_stack` 来标识栈底的位置，它们都被设置为全局符号供其他目标文件使用。

在链接脚本 `linker.ld` 中可以看到 `.bss.stack` 段最终会被汇集到 `.bss` 段中：

```assembly
.bss : {
    *(.bss.stack)
    sbss = .;
    *(.bss .bss.*)
    *(.sbss .sbss.*)
}
ebss = .;
```

全局符号 `sbss` 和 `ebss` 分别指向 `.bss` 段除 `.bss.stack` 以外的起始和终止地址，我们在使用这部分数据之前需要将它们初始化为零，main.rs如下：

注意：

1.需要通过宏将 `rust_main` 标记为 `#[no_mangle]` 以避免编译器对它的名字进行混淆，不然在链接的时候， `entry.asm` 将找不到 `main.rs` 提供的外部符号 `rust_main` 从而导致链接失败。

2.在函数 `clear_bss` 中，我们会尝试从其他地方找到全局符号 `sbss` 和 `ebss` ，它们由链接脚本 `linker.ld` 给出，并分别指出需要被清零的 `.bss` 段的起始和终止地址。接下来我们只需遍历该地址区间并逐字节进行清零即可。

3.**外部符号引用**：extern “C” 可以引用一个外部的 C 函数接口（这意味着调用它的时候要遵从目标平台的 C 语言调用规范）。但我们这里只是引用位置标志并将其转成 usize 获取它的地址。由此可以知道 `.bss` 段两端的地址。

```rust
// os//src/main.rs
#![no_std]
#![no_main]
mod lang_items;
use core::arch::global_asm;
global_asm!(include_str!("entry.asm"));

#[no_mangle]
pub fn rust_main() -> ! {
    clear_bss();
    loop{}
}

fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    for a in (sbss as usize..ebss as usize) {
        unsafe {
            (a as *mut usize).write_volatile(0);
        }
    }
}
```

## 基于 SBI 服务完成输出和关机

当需要使用 RustSBI 服务的时候调用sbi_call就行了

```rust
#![allow(unused)]
const SBI_SET_TIMER: usize = 0;
const SBI_CONSOLE_PUTCHAR: usize = 1;
// 定义 RustSBI 支持的服务类型常量
const SBI_CONSOLE_GETCHAR: usize = 2;
const SBI_CLEAR_IPI: usize = 3;
const SBI_SEND_IPI: usize = 4;
const SBI_REMOTE_FENCE_I: usize = 5;
const SBI_REMOTE_SFENCE_VMA: usize = 6;
const SBI_REMOTE_SFENCE_VMA_ASID: usize = 7;
const SBI_SHUTDOWN: usize = 8;

use core::arch::asm;
#[inline(always)]
fn sbi_call(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret;
    unsafe {
        asm!(
            "ecall",
            inlateout("x10") arg0 => ret,
            in("x11") arg1,
            in("x12") arg2,
            in("x17") which,
        );
    }
    ret
}
```

服务 SBI_CONSOLE_PUTCHAR 可以用来在屏幕上输出一个字符。
我们将这个功能封装成 console_putchar 函数

```rust
pub fn console_putchar(c: usize) {
    sbi_call(SBI_CONSOLE_PUTCHAR, c, 0, 0);
}
```

将关机服务 SBI_SHUTDOWN 封装成 shutdown 函数：

```rust
pub fn shutdown() -> ! {
    sbi_call(SBI_SHUTDOWN, 0, 0, 0);
    panic!("It should shutdown!");
}
```

打印OK：

```rust
use sbi::{console_putchar, shutdown};
pub fn rust_main() -> ! {
    clear_bss();
    console_putchar(79);
    console_putchar(75);
    shutdown();
}
```

![image-20220319202841778](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041732890.png)

### 实现格式化输出

编写基于 `console_putchar` 的 `println!` 宏。

`core::fmt::Write` trait 包含一个用来实现 `println!` 宏很好用的 `write_fmt` 方法，为此我们准备为结构体 `Stdout` 实现 `Write` trait 。在 `Write` trait 中， `write_str` 方法必须实现，因此我们需要为 `Stdout` 实现这一方法，它并不难实现，只需遍历传入的 `&str` 中的每个字符并调用 `console_putchar` 就能将传入的整个字符串打印到屏幕上。

在此之后 `Stdout` 便可调用 `Write` trait 提供的 `write_fmt` 方法并进而实现 `print` 函数。在声明宏 `print!` 和 `println!` 中会调用 `print` 函数完成输出。

```rust
// os/src/console.rs
use crate::sbi::console_putchar;
use core::fmt::{self, Write};

struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            console_putchar(c as usize);
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments) {
    Stdout.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
```

现在我们可以在 `rust_main` 中使用 `print!` 和 `println!` 宏进行格式化输出了

```rust
#[no_mangle]
pub fn rust_main() -> ! {
    clear_bss();
    println!("Hello World!");
    shutdown();
}
```

![image-20220319204036189](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041732098.png)

### 处理致命错误

之前的实现：**遇到不可恢复错误的时候，被标记为语义项** `#[panic_handler]` **的** `panic` **函数将会被调用**，然而其中只是一个死循环，会使得计算机卡在这里。

```rust
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

我们尝试打印更加详细的信息，**包括 panic 所在的源文件和代码行数**。我们尝试从传入的 `PanicInfo` 中解析这些信息，如果解析成功的话，就和 panic 的报错信息一起打印出来。我们需要在 `main.rs` 开头加上 `#![feature(panic_info_message)]` 才能通过 `PanicInfo::message` 获取报错信息。当打印完毕之后，我们直接调用 `shutdown` 函数关机。

**注意：导入println宏需要在开头使用**

```rust
use crate::println
```

lang_item.rs中的panic函数（panic宏）实现如下：

```rust
use core::panic::PanicInfo;
use crate::{sbi::shutdown, println};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        println!(
            "Panicked at {}:{} {}",
            location.file(),
            location.line(),
            info.message().unwrap()
        );
    } else {
        println!("Panicked: {}", info.message().unwrap());
    }
    shutdown()
}
```

测试：可以看到，panic 所在的源文件和代码行数被正确报告，这将为我们后续章节的开发和调试带来很大方便。

```rust
#[no_mangle]
pub fn rust_main() -> ! {
    clear_bss();
    println!("Hello World!");
    // shutdown();
    panic!("Shutdown machine!");
}
```

![image-20220319210756062](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041732855.png)

# 批处理系统

## 实现自己的“标准库”和应用程序

### 目录结构

应用程序、用户库（包括入口函数、初始化函数、I/O 函数和系统调用接口等多个 rs 文件组成）放在项目根目录的 `user` 目录下，它和第一章的裸机应用不同之处主要在项目的目录文件结构和内存布局上：

- `user/src/bin/*.rs` ：各个应用程序
- `user/src/*.rs` ：用户库（包括入口函数、初始化函数、I/O 函数和系统调用接口等）
- `user/src/linker.ld` ：应用程序的内存布局说明。

在根目录下创建U特权级下的支持库（用户态应用程序的运行库）：

```
cargo new user --lib
```

修改cargo.toml文件，将此库名修改为user_lib，在user/src下建立新文件夹bin，bin里面有多个程序的源代码

### 库的入口

要实现应用程序，首先需要实现我们自己的“标准库”，这是因为**编程语言相关的标准库需要在执行应用程序之前进行一些初始化工作。**

先搭个架子：lib.rs

在 `lib.rs` 中我们定义了用户库的入口点 `_start` ：

```rust
#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start() -> ! {
    clear_bss();
    exit(main());
    panic!("unreachable after sys_exit!");
}
```

第 2 行使用 Rust 的宏将 `_start` 这段代码编译后的汇编代码中放在一个名为 `.text.entry` 的代码段中，方便我们在后续链接的时候调整它的位置**使得它能够作为用户库的入口，亦即之后构建的应用程序的入口**。

从第 4 行开始，进入用户库入口之后，首先和第一章一样，手动清空需要零初始化的 `.bss` 段（很遗憾到目前为止底层的批处理系统还没有这个能力，所以我们只能在用户库中完成）；然后调用 `main` 函数得到一个类型为 `i32` 的返回值，最后调用用户库提供的 `exit` 接口退出应用程序，并将 `main` 函数的返回值告知批处理系统。

关于extern关键字，请参考：[Rust FFI 编程 - Rust 语言层面对 FFI 的支持](https://blog.csdn.net/u012067469/article/details/105571144)

在lib.rs中还实现了另一个main函数：

```rust
#[no_mangle]
#[linkage = "weak"]
fn main() -> i32 {
    panic!("Cannot find main!");
}
```

使用宏#[linkage=“weak”]，将函数符号main标志为弱链接。最后链接的时候，虽然在 `lib.rs` 和 `bin` 目录下的某个应用程序都有 `main` 符号，但由于 `lib.rs` 中的 `main` 符号是弱链接，链接器会使用 `bin` 目录下的应用主逻辑作为 `main`。这样做的主要目的是进行某种程度上的**保护**，**如果在 `bin` 目录下找不到任何 `main` ，那么编译也能够通过，但会在运行时报错。**

为了支持上述这些链接操作，我们需要在 `lib.rs` 的开头加入：

```rust
#![feature(linkage)]
```

在 `user/.cargo/config` 中，我们和第一章一样设置链接时使用链接脚本 `user/src/linker.ld` 。

```rust
# user/.cargo/config
[build]
target = "riscv64gc-unknown-none-elf"

[target.riscv64gc-unknown-none-elf]
rustflags = [
    "-Clink-arg=-Tsrc/linker.ld", "-Cforce-frame-pointers=yes"
]
```

设置链接脚本：

- 将程序的起始物理地址调整为 `0x80400000` ，三个应用程序都会被加载到这个物理地址上运行；
- 将 `_start` 所在的 `.text.entry` 放在整个程序的开头，也就是说批处理系统只要在加载之后跳转到 `0x80400000` 就已经进入了 用户库的入口点，并会在初始化之后跳转到应用程序主逻辑；
- 提供了最终生成可执行文件的 `.bss` 段的起始和终止地址，方便 `clear_bss` 函数使用。

```assembly
/* user/src/liinker.ld */
OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x80400000;

SECTIONS
{
    . = BASE_ADDRESS;
    .text : {
        *(.text.entry)
        *(.text .text.*)
    }
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }
    .bss : {
        start_bss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        end_bss = .;
    }
    /DISCARD/ : {
        *(.eh_frame)
        *(.debug*)
    }
}
```

其余的部分和第一章基本相同。

目录结构：

![image-20220320164652583](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041732016.png)

现在还缺少两个系统调用的实现——分别是sys_write和sys_exit，如下图，报错原因正是因为缺少实现

![image-20220320164827964](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041732125.png)

在_start函数中，缺少exit函数，因此我们需要编写sys_exit函数

在console.rs中，过去我们通过RustSBI提供的功能来实现字符的的输出，但现在我们写的不是内核（S特权级），而是用户态应用程序所依赖的库（U特权级），所以我们不能直接使用RustSBI（M特权级）提供的功能来输出字符串了

![image-20220320164943533](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041732525.png)

同理，对于lang_items.rs中的报错，原因也是如此

![image-20220320165002690](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041732851.png)

### 编写系统调用syscall

于是，现在的任务就是编写系统调用，即实现user_lib库的子模块——syscall.rs

在子模块 `syscall` 中，应用程序通过 `ecall` 调用批处理系统提供的接口，由于应用程序运行在用户态（即 U 模式）， `ecall` 指令会触发名为 *Environment call from U-mode* 的异常，并 Trap 进入 S 模式执行批处理系统针对这个异常特别提供的服务代码。

在 RISC-V 的系统调用规范中，寄存器 `a0~a6` 保存系统调用的参数， `a0` 保存系统调用的返回值，寄存器 `a7` 用来传递 syscall ID，需要在代码中使用内嵌汇编来完成参数/返回值绑定和 `ecall` 指令的插入：

```rust
// user/src/syscall.rs
use core::arch::asm;
fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;
    unsafe {
        asm!(
            "ecall",
            inlateout("x10") args[0] => ret,
            in("x11") args[1],
            in("x12") args[2],
            in("x17") id
        );
    }
    ret
}
```

我们曾经使用 `global_asm!` 宏来嵌入全局汇编代码，而这里的 `asm!` 宏可以将汇编代码嵌入到局部的函数上下文中。相比 `global_asm!` ， `asm!` 宏可以获取上下文中的变量信息并允许嵌入的汇编代码对这些变量进行操作。由于编译器的能力不足以判定插入汇编代码这个行为的安全性，所以我们需要将其包裹在 unsafe 块中自己来对它负责。

`in("x11") args[1]` 则表示将输入参数 `args[1]` 绑定到 `ecall` 的输入寄存器 `x11` 即 `a1` 中，编译器自动插入相关指令并保证在 `ecall` 指令被执行之前寄存器 `a1` 的值与 `args[1]` 相同。比较特殊的是 `a0` 寄存器，它**同时作为输入和输出**，因此我们将 `in` 改成 `inlateout` ，并在行末的变量部分使用 `{in_var} => {out_var}` 的格式

### 实现sys_write和sys_exit

实现sys_write和sys_exit只需要对syscall进行封装，实现如下

**注意：**

`sys_write` 使用一个 `&[u8]` 切片类型来描述缓冲区，这是一个 **胖指针** (Fat Pointer)，里面既包含缓冲区的起始地址，还 包含缓冲区的长度。我们可以分别通过 `as_ptr` 和 `len` 方法取出它们并独立地作为实际的系统调用参数。

```rust
const SYSCALL_WRITE: uize = 64;
const SYSCALL_EXIT: uszie = 93;

pub fn sys_write(fd: usize, buffer: &[u8]) -> isize {
    syscall(SYSCALL_WRITE, [fd, buffer.as_ptr() as usize, buffer.len()])
}

pub fn sys_exit(xstate: i32) -> isize {
    syscall(SYSCALL_EXIT, [xstate as usize, 0, 0]);
}
```

将sys_write和sys_exit在user_lib中进一步封装

```rust
// user/src/lib.rs
mod syscall;// import his child module syscall.rs
use syscall::{sys_write, sys_exit};

pub fn write(fd: usize, buf: &[u8]) -> isize{
    sys_write(fd, buf)
}

pub fn exit(exit_code: i32) -> isize {
    sys_exit(exit_code)
}
```

改写console.rs，不用像前一章中那样再使用sbi的功能，把 `Stdout::write_str` 改成基于 `write` 的实现，且传入的 `fd` 参数设置为 1，它代表标准输出， 也就是输出到屏幕。目前我们不需要考虑其他的 `fd` 选取情况。这样，应用程序的 `println!` 宏借助系统调用变得可用了。

```rust
use super::write;// import 'writte' from his father lib.rs
struct Stdout;
const STDOUT: usize = 1;
impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write(STDOUT, s.as_bytes());
        Ok(())
    }
}
pub fn print(args: fmt::Arguments) {
    Stdout.write_fmt(args).unwrap();
}
```

编写makefile，它位于user目录下

```makefile
TARGET := riscv64gc-unknown-none-elf
MODE := release
APP_DIR := src/bin
TARGET_DIR := target/$(TARGET)/$(MODE)
APPS := $(wildcard $(APP_DIR)/*.rs)
ELFS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%, $(APPS))
BINS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%.bin, $(APPS))

OBJDUMP := rust-objdump --arch-name=riscv64
OBJCOPY := rust-objcopy --binary-architecture=riscv64

elf:
    @cargo build --release
    @echo $(APPS)
    @echo $(ELFS)
    @echo $(BINS)

binary: elf
    $(foreach elf, $(ELFS), $(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.bin, $(elf));)

build: binary
```

修改Cargo.toml

```toml
[dependencies]
riscv = { git = "https://github.com/rcore-os/riscv", features = ["inline-asm"] } 
```

### 得到应用程序

03和04是两个尝试在U模式下使用S特权指令的程序，源代码如下，我们将使用qemu-riscv64（类似于一台预装可Linux操作系统的RISC-V架构的计算机，仅支持载入并执行单个可执行文件）来试着运行

```
// user/src/bin/03priv_inst.rs
use core::arch::asm;
#[no_mangle]
fn main() -> i32 {
    println!("Try to execute privileged instruction in U Mode");
    println!("Kernel should kill this application!");
    unsafe {
        asm!("sret");
    }
    0
}

// user/src/bin/04priv_csr.rs
use riscv::register::sstatus::{self, SPP};
#[no_mangle]
fn main() -> i32 {
    println!("Try to access privileged CSR in U Mode");
    println!("Kernel should kill this application!");
    unsafe {
        sstatus::set_spp(SPP::User);
    }
    0
}
```

实验：运行生成的应用程序

![image-20220323180647038](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041733606.png)

qemu-riscv64可以解析基于 RISC-V 的应用级 ELF 可执行文件，加载到内存并跳转到入口点开始执行。在翻译并执行指令时，**如果碰到是系统调用相关的汇编指令，它会把不同处理器（如 RISC-V）的 Linux 系统调用转换为本机处理器（如 x86-64）上的 Linux 系统调用**，这样就可以让本机 Linux 完成系统调用，并返回结果（再转换成 RISC-V 能识别的数据）给这些应用。

## 实现批处理操作系统

批处理操作系统：每当一个应用程序执行完毕，都需要将下一个要执行的应用程序的代码和数据加载到内存。因此要从实现应用程序的加载机制开始。

### 应用管理器——AppManager

应用管理器的目的是找到并加载应用程序的二进制码到物理内存中，他的主要功能是：1、保存应用数量和各自的位置信息，以及当前执行到第几个应用。2、根据应用程序的位置信息，初始化好应用所需的内存空间，并加载应用执行。

其结构体定义如下：

```
struct AppManager {
    num_app: usize,
    current_app: usize,
    app_start: [usize; MAX_APP_NUM + 1],
}
```

用于保存上面提到的各类信息

```
pub struct UPSafeCell<T> {
    /// inner data
    inner: RefCell<T>,
}

unsafe impl<T> Sync for UPSafeCell<T> {}

impl<T> UPSafeCell<T> {
    /// User is responsible to guarantee that struct is only used in
    /// uniprocessor
    pub unsafe fn new(value: T) -> Self {
        Self{inner: RefCell::new(value)}
    }
    // Panic if the data has been borrowed
    pub fn exclusive_access(&self) -> RefMut<'_, T> {
        self.inner.borrow_mut()
    }
}
```

### 在单核上安全使用可变全局变量

Rust 对于并发安全的检查较为粗糙，当声明一个全局变量的时候，编译器会默认程序员会在多线程上使用它，而并不会检查程序员是否真的这样做。如果一个变量实际上仅会在单线程上使用，那 Rust 会期待我们将变量分配在栈上作为局部变量而不是全局变量。

但对于内核而言，有些变量无法作为局部变量使用。这是因为后面内核会并发执行多条控制流，这些控制流都会用到这些变量。如果我们最初将变量分配在某条控制流的栈上，那么我们就需要考虑如何将变量传递到其他控制流上，由于控制流的切换等操作并非常规的函数调用，我们很难将变量传递出去。因此最方便的做法是使用全局变量，这意味着**在程序的任何地方均可随意访问它们，自然也包括这些控制流。**

```rust
// os/src/sync/up.rs

pub struct UPSafeCell<T> {
    /// inner data
    inner: RefCell<T>,
}

unsafe impl<T> Sync for UPSafeCell<T> {}

impl<T> UPSafeCell<T> {
    /// User is responsible to guarantee that inner struct is only used in
    /// uniprocessor.
    pub unsafe fn new(value: T) -> Self {
        Self { inner: RefCell::new(value) }
    }
    /// Panic if the data has been borrowed.
    pub fn exclusive_access(&self) -> RefMut<'_, T> {
        self.inner.borrow_mut()
    }
}
```

`UPSafeCell` 对于 `RefCell` 简单进行封装，它和 `RefCell` 一样提供内部可变性和运行时借用检查，只是更加严格：调用 `exclusive_access` 可以得到它包裹的数据的独占访问权。因此**当我们要访问数据时（无论读还是写），需要首先调用 `exclusive_access` 获得数据的可变借用标记**，通过它可以完成数据的读写，**在操作完成之后我们需要销毁这个标记**，此后才能开始对该数据的下一次访问。**相比 `RefCell` 它不再允许多个读操作同时存在**。

**再次强调：无论读还是写UPSafeCell结构体中的RefCell变量，都需要通过exclusive_access这个唯一的接口来进行，以确保读写的安全性。**

这段代码里面出现了两个 `unsafe` ：

- 首先 `new` 被声明为一个 `unsafe` 函数，是因为我们希望使用者在创建一个 `UPSafeCell` 的时候保证在访问 `UPSafeCell` 内包裹的数据的时候始终不违背上述模式：即访问之前调用 `exclusive_access` ，访问之后销毁借用标记再进行下一次访问。这只能依靠使用者自己来保证，但我们提供了一个保底措施：当使用者违背了上述模式，比如访问之后忘记销毁就开启下一次访问时，程序会 panic 并退出。
- 另一方面，我们将 `UPSafeCell` 标记为 `Sync` 使得它可以作为一个全局变量。这是 unsafe 行为，因为编译器无法确定我们的 `UPSafeCell` 能否安全的在多线程间共享。而我们能够向编译器做出保证，第一个原因是**目前我们内核仅运行在单核上，因此无需在意任何多核引发的数据竞争/同步问题**；第二个原因则是**它基于 `RefCell` 提供了运行时借用检查功能**，从而满足了 Rust 对于借用的基本约束进而保证了内存安全。

**上述内容还存在一些没太理解的地方，暂时留置**

### 分批处理

#### 将程序加载到内存

link_app.S文件内容如下，根据教程，它是使用make run自动生成的，我们这里手动生成：

```assembly
# os/src/link_app.S

    .align 3
    .section .data
    .global _num_app
_num_app:
    .quad 5
    .quad app_0_start
    .quad app_1_start
    .quad app_2_start
    .quad app_3_start
    .quad app_4_start
    .quad app_4_end

    .section .data
    .global app_0_start
    .global app_0_end
app_0_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/00hello_world.bin"
app_0_end:

    .section .data
    .global app_1_start
    .global app_1_end
app_1_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/01store_fault.bin"
app_1_end:

    .section .data
    .global app_2_start
    .global app_2_end
app_2_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/02power.bin"
app_2_end:

    .section .data
    .global app_3_start
    .global app_3_end
app_3_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/03priv_inst.bin"
app_3_end:

    .section .data
    .global app_4_start
    .global app_4_end
app_4_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/04priv_csr.bin"
app_4_end:
```

从该文件中不难看出，在本节中，我们是把这些应用程序和内核的data section（数据段）整合到了一起，让**应用程序的二进制镜像成为内核数据的一部分**，加载应用就是把内核的一部分数据拷贝到物理内存的指定位置0x80400000。在这一点上也体现了冯诺依曼计算机的 **代码即数据 **的特征。

接下来以尽量少的unsafe code来初始化App Manager的全局实例——APP_MANAGER：

注意：这里我们使用了外部库 `lazy_static` 提供的 `lazy_static!` 宏。要引入这个外部库，我们需要加入依赖：

```toml
# os/Cargo.toml
[dependencies]
lazy_static = { version = "1.4.0", features = ["spin_no_std"] }
```

`lazy_static!` 宏提供了全局变量的运行时初始化功能。一般情况下，**全局变量（比如下面代码中的全局变量APP_MANAGER）必须在编译期设置一个初始值**，但是**有些全局变量（同样是APP_MANAGER）依赖于运行期间才能得到的数据作为初始值**。这导致这些全局变量需要在运行时发生变化，即需要重新设置初始值之后才能使用。如果我们手动实现的话有诸多不便之处，比如需要把这种全局变量声明为 `static mut` 并衍生出很多 unsafe 代码 。这种情况下我们可以使用 `lazy_static!` 宏来帮助我们解决这个问题。这里我们借助 `lazy_static!` 声明了一个 `AppManager` 结构的名为 `APP_MANAGER` 的全局实例，且只有在它第一次被使用到的时候，才会进行实际的初始化工作。

```rust
// os/src/batch.rs
struct AppManager {
    num_app: usize,
    current_app: usize,
    app_start: [usize; MAX_APP_NUM + 1],
}

lazy_static! {
    static ref APP_MANAGER: UPSafeCell<AppManager> = unsafe {
        UPSafeCell::new({
            extern "C" {
                fn _num_app();// 找到 link_app.S 中提供的符号 _num_app
            }
            let num_app_ptr = _num_app as usize as *const usize;
            let num_app = num_app_ptr.read_volatile();
            let mut app_start: [usize; MAX_APP_NUM + 1] = [0; MAX_APP_NUM + 1];
            // 从这里开始解析出应用数量以及各个应用的起始地址
            let app_start_raw: &[usize] = core::slice::from_raw_parts(
                num_app_ptr.add(1), num_app + 1
            );
            app_start[..=num_app].copy_from_slice(app_start_raw);
            AppManager {
                num_app,
                current_app: 0,
                app_start,
            }
        })
    };
}
```

注：batch v.分批处理

最终batch.rs实现如下：

```rust
use core::arch::asm;

use lazy_static::*;

// os/src/batch.rs
use crate::sync::UPSafeCell;
use crate::trap::TrapContext;

const USER_STACK_SIZE: usize = 4096 * 2;
const KERNEL_STACK_SIZE: usize = 4096 * 2;
const MAX_APP_NUM: usize = 16;
const APP_BASE_ADDRESS: usize = 0x80400000;
const APP_SIZE_LIMIT: usize = 0x20000;

struct AppManager {
    num_app: usize,
    // 总应用程序的数量
    current_app: usize,
    // 指示当前应该运行的程序
    app_start: [usize; MAX_APP_NUM + 1],// app_start指向每个程序的指令入口点
}

lazy_static! {
    static ref APP_MANAGER: UPSafeCell<AppManager> = unsafe {
        UPSafeCell::new({
            extern "C" {
                fn _num_app();// 找到 link_app.S 中提供的符号 _num_app
            }
            let num_app_ptr = _num_app as usize as *const usize;
            let num_app = num_app_ptr.read_volatile();
            let mut app_start: [usize; MAX_APP_NUM + 1] = [0; MAX_APP_NUM + 1];
            // 从这里开始解析出应用数量以及各个应用的起始地址
            let app_start_raw: &[usize] = core::slice::from_raw_parts(
                num_app_ptr.add(1), num_app + 1
            );
            app_start[..=num_app].copy_from_slice(app_start_raw);
            AppManager {
                num_app,
                current_app: 0,
                app_start,
            }
        })
    };
}

impl AppManager {
    // print the number of loaded apps
    // and start&end addr of loaded apps
    pub fn print_app_info(&self) {
        println!("[kernel] num_app = {}", self.num_app);
        for i in 0..self.num_app {
            // print start_addr and end_addr
            println!(
                "[kernel] app_{} [{:#x}, {:#x})",
                i,
                self.app_start[i],
                self.app_start[i + 1]
            );
        }
    }

    pub fn get_current_app(&self) -> usize {
        self.current_app
    }

    pub fn move_to_next_app(&mut self) {
        self.current_app += 1;
    }

    // 负责将参数 app_id 对应的应用程序的二进制镜像
    // 加载到物理内存以 0x80400000 起始的位置
    unsafe fn load_app(&self, app_id: usize) {
        if app_id >= self.num_app {
            panic!("All applications completed!");
        }
        println!("[kernel] Loading app_{}", app_id);
        // clear icache
        asm!("fence.i");
        // clear app area
        core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, APP_SIZE_LIMIT).fill(0);
        // app_src是第app_id个程序原始数据的不可变切片，长度为后一个程序的起始地址减去这个程序的起始地址
        let app_src = core::slice::from_raw_parts(
            self.app_start[app_id] as *const u8,
            self.app_start[app_id + 1] - self.app_start[app_id],// app_start：指向每个应用程序的入口点的指针组成的usize数组
        );
        // app_dst是一个起始地址为0x804000000，长度为第app_id个程序长度的可变切片
        let app_dst = core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, app_src.len());
        // load to memory
        app_dst.copy_from_slice(app_src);
    }
}

pub fn init() {
    print_app_info();
}

pub fn print_app_info() {
    APP_MANAGER.exclusive_access().print_app_info();
}

// KernelStack and UserStack
#[repr(align(4096))]
struct KernelStack {
    data: [u8; KERNEL_STACK_SIZE],
}

#[repr(align(4096))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}

static KERNEL_STACK: KernelStack = KernelStack {
    data: [0; KERNEL_STACK_SIZE],
};
static USER_STACK: UserStack = UserStack {
    data: [0; USER_STACK_SIZE],
};

// get_sp 方法来获取栈顶地址
impl UserStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
}

impl KernelStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + KERNEL_STACK_SIZE
    }
    // 此时在S特权级，目的是传入上下文
    // 向内核栈中push app初始化所需的上下文
    // 返回指向内核栈顶KernelStack的静态可变指针
    pub fn push_context(&self, cx: TrapContext) -> &'static mut TrapContext {
        // 扩栈，返回指向内核栈顶KernelStack的可变指针，指针类型是*mut TrapContext
        let cx_ptr = (self.get_sp() - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe {
            *cx_ptr = cx;
        }
        unsafe { cx_ptr.as_mut().unwrap() }
    }
}

// 运行下一个app
pub fn run_next_app() -> ! {
    let mut app_manager = APP_MANAGER.exclusive_access();
    let current_app = app_manager.get_current_app();
    unsafe {
        app_manager.load_app(current_app);
    }
    app_manager.move_to_next_app();
    drop(app_manager);
    // before this we have to drop local variables related to resources manually
    // and release the resources
    extern "C" {
        fn __restore(cx_addr: usize);
    }
    unsafe {
        __restore(KERNEL_STACK.push_context(TrapContext::app_init_context(
            APP_BASE_ADDRESS,
            USER_STACK.get_sp(),
        )) as *const _ as usize);
    }
    panic!("Unreachable in batch::run_current_app!");
}
```

汇编指令`fence.i` ，它是用来清理 i-cache 的。我们知道缓存是存储层级结构中提高访存速度的很重要一环。而 CPU 对物理内存所做的缓存又分成 **数据缓存** (d-cache) 和 **指令缓存** (i-cache) 两部分，分别在 CPU 访存和取指的时候使用。在取指的时候，对于一个指令地址， CPU 会先去 i-cache 里面看一下它是否在某个已缓存的缓存行内，如果在的话它就会直接从高速缓存中拿到指令而不是通过总线访问内存。通常情况下， CPU 会认为程序的代码段不会发生变化，因此 i-cache 是一种只读缓存。但在这里，OS将修改会被 CPU 取指的内存区域，这会使得 **i-cache 中含有与内存中不一致的内容**。因此OS在这里必须使用 `fence.i` 指令手动清空 i-cache ，让里面所有的内容全部失效，才能够保证CPU访问内存数据和代码的正确性。

>   在执行第一个应用之前清空icache确实没用，因为那个时候icache里面还没有相关内容。但是在执行后面应用的时候，icache里面就会缓存上一个应用的指令，因此需要手动清空它。——wyf(THU)

意思是，一个应用的指令被加载到0x80400000，执行完后，批处理操作系统需要将将一个新的应用加载到该位置，该位置也就有了新的指令，CPU执行该处的指令时，会发现当前该地址的指令和缓存中的指令不一致，报错。

#### 对外暴露接口

- `init` ：调用 `print_app_info` 的时候第一次用到了全局变量 `APP_MANAGER` ，它也是在这个时候完成初始化；
- `run_next_app` ：批处理操作系统的核心操作，即加载并运行下一个应用程序。当批处理操作系统完成初始化或者一个应用程序运行结束或出错之后会调用该函数。

```
// os/src/batch.rs
pub fn init() {
    print_app_info();
}

pub fn print_app_info() {
    APP_MANAGER.exclusive_access().print_app_info();
}
```

## 特权级切换

在 RISC-V 架构中，关于 Trap 有一条重要的规则：在 Trap 前的特权级不会高于 Trap 后的特权级。因此如果触发 Trap 之后切换到 S 特权级（下称 Trap 到 S），说明 Trap 发生之前 CPU 只能运行在 S/U 特权级。

### RISC-V架构处理器硬件提供的支持

无论如何，只要是 Trap 到 S 特权级，操作系统就会使用 S 特权级中与 Trap 相关的 **控制状态寄存器** (CSR, Control and Status Register) 来辅助 Trap 处理。我们在编写运行在 S 特权级的批处理操作系统中的 Trap 处理相关代码的时候，就需要使用如下所示的 S 模式的 CSR 寄存器。

| CSR 名   | 该 CSR 与 Trap 相关的功能                            |
| ------- | --------------------------------------------- |
| sstatus | `SPP` 等字段给出 Trap **发生之前** CPU 处在哪个特权级（S/U）等信息 |
| sepc    | 当 Trap 是一个异常的时候，记录 Trap **发生之前**执行的最后一条指令的地址  |
| scause  | 描述 Trap 的原因                                   |
| stval   | 给出 Trap 附加信息                                  |
| stvec   | 控制 Trap 处理代码的入口地址                             |

**其中，sstatus是S特权级下最重要的CSR**

当用户态的程序执行ecall指令，并准备从用户特权级Trap到S特权级的时候，硬件**自动完成**：

- `sstatus` 的 `SPP` 字段会被修改为 CPU 当前的特权级（U/S）。
- `sepc` 会被修改为 ecall 这一条指令的地址。
- `scause/stval` 分别会被修改成这次 Trap 的原因以及相关的附加信息。
- CPU 会跳转到 `stvec` 所设置的 Trap 处理入口地址，并将当前特权级设置为 S ，然后从Trap 处理入口地址处开始执行。

>   **stvec 相关细节**
> 
>   在 RV64 中， `stvec` 是一个 64 位的 CSR，在中断使能的情况下，保存了中断处理的入口地址。它有两个字段：
> 
> - MODE 位于 [1:0]，长度为 2 bits；
> 
> - BASE 位于 [63:2]，长度为 62 bits。
>   
>   当 MODE 字段为 0 的时候， `stvec` 被设置为 Direct 模式，此时进入 S 模式的 Trap 无论原因如何，处理 Trap 的入口地址都是 `BASE<<2` ， CPU 会跳转到这个地方进行异常处理。本书中我们只会将 `stvec` 设置为 Direct 模式。而 `stvec` 还可以被设置为 Vectored 模式。这里暂时不用详细了解了。

而当 CPU 完成 Trap 处理准备返回的时候，需要通过一条 S 特权级的特权指令 `sret` 来完成，这一条指令具体完成以下功能：

- CPU 会将当前的特权级按照 `sstatus` 的 `SPP` 字段设置为 U 或者 S ；
- CPU 会跳转到 `sepc` 寄存器指向的那条指令，然后继续执行。

### 用户栈与内核栈

在 Trap 触发的一瞬间， CPU 就会切换到 S 特权级并跳转到 `stvec` 所指示的位置。但是在正式进入 S 特权级的 Trap 处理之前，上面 提到过我们必须保存原控制流的寄存器状态，这一般通过内核栈来保存。注意，我们需要用专门为操作系统准备的内核栈，而不是应用程序运行时用到的用户栈。

使用两个不同的栈主要是为了**安全性**：如果两个控制流（即应用程序的控制流和内核的控制流）使用同一个栈，在返回之后应用程序就能读到 Trap 控制流的历史信息，比如内核一些函数的地址，这样会带来安全隐患。于是，我们要做的是，**在批处理操作系统中添加一段汇编代码，实现从用户栈切换到内核栈，并在内核栈上保存应用程序控制流的寄存器状态。**

#### 用户栈和内核栈的数据结构

于是，声明两个类型KernelStack和UserStack分别表示用户栈和内核栈，它们都只是字节数组的简单包装

```rust
const USER_STACK_SIZE: usize = 4096 * 2;
const KERNEL_STACK_SIZE: usize = 4096 * 2;

#[repr(align(4096))]
struct KernelStack {
    data: [u8; KERNEL_STACK_SIZE],
}

#[repr(align(4096))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}

static KERNEL_STACK: KernelStack = KernelStack {
    data: [0; KERNEL_STACK_SIZE],
};
static USER_STACK: UserStack = UserStack {
    data: [0; USER_STACK_SIZE],
};
```

常数 `USER_STACK_SIZE` 和 `KERNEL_STACK_SIZE` 指出内核栈和用户栈的大小分别为 8KiB 。KernelStack和UserStack这两个类型是以**全局变量**的形式实例化在批处理操作系统的 `.bss` 段中的。#[repr(align(4096))]保证其在4KiB边界上对齐，这一要求确保栈总是填满完整的页面，并允许优化，使条目非常紧凑，同时也保证了内核栈和用户栈在不同的页面上，不会重合，保证了安全性。

获得栈底地址（sp）注意栈是从高地址往低地址增长的

```rust
// get_sp 方法来获取栈顶地址
impl UserStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
}

impl KernelStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + KERNEL_STACK_SIZE
    }
}
```

于是换栈只需将sp寄存器的值修改为get_sp的返回值即可。

### Trap

#### Trap上下文的数据结构

Trap上下文即在Trap发生时需要保存的物理资源内容，不是说只用保存用户应用程序的上下文吗？为什么Trap发生时也要保存呢？这是因为：

- 虽然在 Trap 控制流中只是会执行 Trap 处理相关的代码，但依然可能直接或间接调用很多模块，因此很难甚至不可能找出哪些寄存器无需保存。既然如此我们就只能**全部保存**了。但这里也有一些例外，如 `x0` 被硬编码为 0 ，它自然不会有变化；还有 `tp(x4)` 寄存器，除非我们手动出于一些特殊用途使用它，否则**一般也不会被用到**。虽然它们无需保存，但我们仍然在 `TrapContext` 中为它们预留空间，主要是为了后续的实现方便。
- 对于 CSR ，进入 Trap 的时候，硬件会立即覆盖掉 `scause/stval/sstatus/sepc` 的全部或是其中一部分。`scause/stval` 的情况是：它总是在 Trap 处理的第一时间就被使用或者是在其他地方保存下来了，因此它没有被修改并造成不良影响的风险。而对于 `sstatus/sepc` 而言，它们会在 Trap 处理的全程有意义（在 Trap 控制流最后 `sret` 的时候还用到了它们），而且确实会出现 **Trap 嵌套的情况使得它们的值被覆盖掉**。所以我们需要将它们也一起保存下来，并在 `sret` 之前恢复原样。
- **总而言之：sstatus和sepc和32个通用寄存器需要保存到一个结构体里面**

Trap上下文的数据结构TrapContext如下：

>   这是最重要的数据表示(repr)。它出现的目的很简单就是和C保持一致，成员字段的顺序、大小和对齐方式和你在C或C++所见到的一模一样的。任何希望跨越FFI边界的类型都应该有repr(C)，因为C是编程世界的通用语言。
> 
>   关于repr，你应该知道的：https://zhuanlan.zhihu.com/p/203504719

```rust
#[repr(C)]
pub struct TrapContext {
    pub x: [usize; 32],
    pub sstaus: Sstatus,
    pub sepc: usize,
}
```

#### Trap上下文的保存与恢复

上下文的保存和恢复，要按照前面的数据结构TrapContext的结构来，也就是说，保存在内存中的数据排布要和该结构体内的排布一致。由于上下文（也就是**32个通用寄存器和sstatus以及sepc**）保存在内核栈上，所以内核栈的栈顶指针负责开辟34*8字节（一个寄存器64位也就是8字节）的空间，用来保存这些上下文。

在trap.S中实现了上下文保存与恢复的汇编代码，分别用全局符号 `__alltraps` 和 `__restore` 标记为函数。Trap 处理的总体流程是：首先通过 `__alltraps` 将 Trap 上下文保存在内核栈上，然后跳转到**使用 Rust 编写的** `trap_handler` 函数完成 Trap 分发及处理。当 `trap_handler` 返回之后，使用 `__restore` 从保存在内核栈上的 Trap 上下文恢复寄存器。最后通过一条 `sret` 指令回到应用程序执行。代码实现如下：

```assembly
.altmacro
.macro SAVE_GP n
    sd x\n, \n*8(sp)
.endm
.macro LOAD_GP n
    ld x\n, \n*8(sp)
.endm
    .section .text
    .globl __alltraps
    .globl __restore
    .align 2
__alltraps:
    csrrw sp, sscratch, sp
    # now sp->kernel stack, sscratch->user stack
    # allocate a TrapContext on kernel stack
    addi sp, sp, -34*8
    # save general-purpose registers
    sd x1, 1*8(sp)
    # skip sp(x2), we will save it later
    sd x3, 3*8(sp)
    # skip tp(x4), application does not use it
    # save x5~x31
    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr
    # we can use t0/t1/t2 freely, because they were saved on kernel stack
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    # read user stack from sscratch and save it on the kernel stack
    csrr t2, sscratch
    sd t2, 2*8(sp)
    # set input argument of trap_handler(cx: &mut TrapContext)
    mv a0, sp
    call trap_handler

__restore:
    # case1: start running app by __restore
    # case2: back to U after handling trap
    mv sp, a0
    # now sp->kernel stack(after allocated), sscratch->user stack
    # restore sstatus/sepc
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    # restore general-purpuse registers except sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # release TrapContext on kernel stack
    addi sp, sp, 34*8
    # now sp->kernel stack, sscratch->user stack
    csrrw sp, sscratch, sp
    sret
```

指令含义参考：[CSRs寄存器的读写指令](https://blog.csdn.net/kuankuan02/article/details/95452616)

#### 汇编代码解读

```assembly
# os/src/trap/trap.S

.macro SAVE_GP n
    sd x\n, \n*8(sp)
.endm

.align 2
__alltraps:
    csrrw sp, sscratch, sp
    # now sp->kernel stack, sscratch->user stack
    # allocate a TrapContext on kernel stack
    addi sp, sp, -34*8
    # save general-purpose registers
    sd x1, 1*8(sp)
    # skip sp(x2), we will save it later
    sd x3, 3*8(sp)
    # skip tp(x4), application does not use it
    # save x5~x31
    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr
    # we can use t0/t1/t2 freely, because they were saved on kernel stack
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    # read user stack from sscratch and save it on the kernel stack
    csrr t2, sscratch
    sd t2, 2*8(sp)
    # set input argument of trap_handler(cx: &mut TrapContext)
    mv a0, sp
    call trap_handler
```

- 第 7 行我们使用 `.align` 将 `__alltraps` 的地址 4 字节对齐，**这是 RISC-V 特权级规范的要求**；

- 第 9 行的 `csrrw` 原型是 csrrw rd, csr, rs 可以将 CSR 当前的值读到通用寄存器 rd 中，然后将通用寄存器 rs 的值写入该 CSR 。因此这里起到的是**交换 sscratch 和 sp 的效果**。**在这一行之前 sp 指向用户栈， sscratch 指向内核栈（原因稍后说明），现在 sp 指向内核栈， sscratch 指向用户栈。**

- 第 12 行，我们准备在内核栈上保存 Trap 上下文，于是预先分配 34×8 字节的栈帧，这里改动的是 sp ，说明确实是在内核栈上。

- 第 13~24 行，保存 Trap 上下文的通用寄存器 x0~x31，**但跳过（不保存） x0 和 tp(x4)**，原因之前已经说明。我们在这里也不保存 sp(x2)，因为我们要基于它来找到每个寄存器应该被保存到的正确的位置。实际上，在栈帧分配之后，我们可用于保存 Trap 上下文的地址区间为 [sp,sp+8×34) ，**按照 `TrapContext` 结构体的内存布局，基于内核栈的位置（sp所指地址）来从低地址到高地址分别按顺序放置 x0~x31这些通用寄存器，最后是 sstatus 和 sepc** 。因此通用寄存器 xn 应该被保存在地址区间 [sp+8n,sp+8(n+1)) 。
  
  **为了简化代码，x5~x31 这 27 个通用寄存器我们通过类似循环的 `.rept` 每次使用 `SAVE_GP` 宏来保存，其实质是相同的。注意我们需要在 `trap.S` 开头加上 `.altmacro` 才能正常使用 `.rept` 命令。**

- 第 25~28 行，我们将 CSR sstatus 和 sepc 的值分别读到寄存器 t0 和 t1 中然后保存到内核栈对应的位置上。指令 csrr rd, csr 的功能就是将 CSR 的值读到寄存器 rd 中。这里我们不用担心 t0 和 t1 被覆盖，因为它们刚刚已经被保存了。

- 第 30~31 行专门处理 sp 的问题。首先将 sscratch 的值读到寄存器 t2 并保存到内核栈上，**注意： 此时sscratch 的值是进入 Trap 之前的 sp 的值，指向用户栈。而现在的 sp 则指向内核栈。**

- 第 33 行令 a0←sp，让寄存器 a0 指向内核栈的栈指针也就是我们刚刚保存的 Trap 上下文的地址，这是由于我们接下来要调用 `trap_handler` 进行 Trap 处理，它的第一个参数 `cx` 由调用规范要从 a0 中获取。而 **Trap 处理函数 `trap_handler` 需要 Trap 上下文的原因在于：它需要知道其中某些寄存器的值，比如在系统调用的时候应用程序传过来的 syscall ID 和对应参数。**我们不能直接使用这些寄存器现在的值，因为它们可能已经被修改了，因此要去内核栈上找已经被保存下来的值。

>   **CSR 相关原子指令**
> 
>   RISC-V 中读写 CSR 的指令是一类能不会被打断地完成多个读写操作的指令。这种不会被打断地完成多个操作的指令被称为 **原子指令** (Atomic Instruction)。这里的 **原子** 的含义是“不可分割的最小个体”，也就是说指令的多个操作要么都不完成，要么全部完成，而不会处于某种中间状态。
> 
>   另外，RISC-V 架构中**常规的数据处理和访存类指令只能操作通用寄存器而不能操作 CSR 。**因此，当想要对 CSR 进行操作时，需要先使用读取 CSR 的指令将 CSR 读到一个通用寄存器中，而后操作该通用寄存器，最后再使用写入 CSR 的指令将该通用寄存器的值写入到 CSR 中。所以在上面的汇编代码中30-31行中，先把scratch寄存器中的值放到t2这个通用的缓存寄存器（Temporaries）中，再把缓存寄存器中的值放到内存中（栈中）
> 
>   再注：要进行 64 位数据传输，RV64 提供了加载和存储双字指令：ld，sd

```assembly
# os/src/trap/trap.S

.macro LOAD_GP n
    ld x\n, \n*8(sp)
.endm

__restore:
    # case1: start running app by __restore
    # case2: back to U after handling trap
    mv sp, a0
    # now sp->kernel stack(after allocated), sscratch->user stack
    # restore sstatus/sepc
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    # restore general-purpuse registers except sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # release TrapContext on kernel stack
    addi sp, sp, 34*8
    # now sp->kernel stack, sscratch->user stack
    csrrw sp, sscratch, sp
    sret
```

- 第 10 行比较奇怪我们暂且不管，假设它从未发生，那么 sp 仍然指向内核栈的栈顶。
- 第 13~26 行负责从内核栈顶的 Trap 上下文恢复通用寄存器和 CSR 。注意我们要先恢复 CSR 再恢复通用寄存器（注意恢复CSR的时候也是先要把内存中的值放到缓存寄存器中，再把缓存寄存器中的值放到CSR寄存器中），这样我们使用的三个临时寄存器才能被正确恢复。
- 在第 28 行之前，sp 指向保存了 Trap 上下文之后的内核栈栈顶， sscratch 指向用户栈栈顶。我们在第 28 行在内核栈上**回收 Trap 上下文所占用的内存**，回归进入 Trap 之前的内核栈栈顶。第 30 行，再次交换 sscratch 和 sp，**现在 sp 重新指向用户栈栈顶，sscratch 也依然保存进入 Trap 之前的状态并指向内核栈栈顶。**
- 在应用程序控制流状态被还原之后，第 31 行我们使用 `sret` 指令回到 U 特权级继续运行应用程序控制流。

>   **sscratch CSR 的用途**
> 
>   在特权级切换的时候，我们需要将 Trap 上下文保存在内核栈上，因此**需要一个寄存器暂存内核栈地址**，并以它**作为基地址指针来依次保存 Trap 上下文的内容**。但是所有的通用寄存器都不能够用作基地址指针，因为它们都需要被保存，如果覆盖掉它们，就会影响后续应用控制流的执行。
> 
>    `sscratch` CSR 正是为此而生。从上面的汇编代码中可以看出，在保存 Trap 上下文的时候，它起到了两个作用：首先是保存了内核栈的地址，其次它可作为一个中转站让 `sp` （目前指向的用户栈的地址）的值可以暂时保存在 `sscratch` 。这样**仅需一条 `csrrw sp, sscratch, sp` 指令（交换对 `sp` 和 `sscratch` 两个寄存器内容）就完成了从用户栈到内核栈的切换**，这是一种极其精巧的实现。

#### Trap分发与处理

在刚才的汇编代码中，已经实现了保存Trap的上下文，现在进行Trap的处理，即实现汇编代码中call的trap_handler函数，它的功能是对于不同的Trap进行处理，当Trap的原因是用户要进行系统调用时，使用系统调用模块（将在后续编写）。当Trap的原因是指令错误、页错误等原因时，打印出相应的提示信息，并运行下一个app(将在后续编写该函数)

```rust
#[no_mangle]
pun fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
    let scause = scause::read();
    let stval = stval::read();
    // 根据 scause 寄存器所保存的 Trap 的原因进行分发处理
    // 这里我们无需手动操作这些 CSR 
    // 而是使用 Rust 的 riscv 库来更加方便的做这些事情。
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.spec += 4;
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        Trap::Exception(Exception::StoreFault) | Trap::Exception(Exception::StorePageFault) => {
            println!("[kernel] PageFault in application, kernel killed it.");
            run_next_app();
        }

        Trap::Exception(Exception::IllegalInstruction) => {
            println!("[kernel] IllegalInstruction in application, kernel killed it.");
            run_next_app();
        }

        _ => {
            panic!("Unsupported trap {:?}, stval = {:#x}!", scause.cause(), stval);
        }
    }
    cx
}
```

代码解读：

- 该函数将传入的Trap上下文结构体的**可变**引用 `cx` 原样返回，因此在 `__restore` 的时候 `a0` 寄存器在调用 `trap_handler` 前后并没有发生变化，**仍然指向分配 Trap 上下文之后的内核栈栈顶**，和此时 `sp` 的值相同，这里的 sp←a0 并不会有问题；
- 第 8 行根据 `scause` 寄存器所保存的 Trap 的原因进行分发处理。这里我们无需手动操作这些 CSR ，而是使用 Rust 的 riscv 库来更加方便的做这些事情。
- 对Trap的原因进行匹配，如果发现原因是来自U特权级的EnvironmentCall (Exception::UserEnvCall)，则修改之前保存在内核栈上的Trap上下文里面的spec，使其增加4

![image-20220326003555040](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041733805.png)

简单回顾一下：在此前实现应用程序的过程中，若应用程序使用系统调用，则都会交给上面图片中的syscall函数进行处理，在此函数中，使用ecall指令触发U特权级到S特权级的Trap，在触发Trap但还没有进入到Trap处理函数（Trap_handler）的时候，硬件帮助我们将sepc设置为ecall指令的地址，因为它是进入 Trap 之前最后一条执行的指令，而ecall**指令字长为4**，因此，我们需要在Trap_handler函数中将sepc+4，这样在__restore的时候sepc在恢复之后就会指向ecall的下一条指令，并在sret之后从哪里开始执行。

这里也顺便回顾一下在Trap上下文中的位次和不同寄存器的功能

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041733467.jpeg)

图片中的x0-x31+sstatus+sepc

```rust
cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
```

cx.x[10]对应的正好是Trap上下文中的a0，即Trap这一过程的返回值，也就是系统调用的返回值

- 分别处理应用程序出现访存错误和非法指令错误的情形。此时需要打印错误信息并调用 `run_next_app` 直接切换并运行下一个应用程序。
- 当遇到目前还不支持的 Trap 类型的时候，panic 报错退出。

### 实现系统调用

对于系统调用而言， **`syscall` 函数并不会实际处理系统调用**，而只是根据 syscall ID 分发到具体的处理函数：

```rust
// os/src/syscall/mod.rs

const SYSCALL_WRITE: usize = 64;
const SYSCALL_EXIT: usize = 93;

mod fs;
mod process;

use fs::*;
use process::*;

pub fn syscall(syscall_id: usize, args: [usize; 3]) -> isize {
    match syscall_id {
        SYSCALL_WRITE => sys_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_EXIT => sys_exit(args[0] as i32),
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}
```

这里我们会将传进来的参数 `args` 转化成能够被具体的系统调用处理函数接受的类型。它们的实现都非常简单：

write系统调用在S级的实现：

```rust
// os/src/syscall/fs.rs

const FD_STDOUT: usize = 1;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let slice = unsafe { core::slice::from_raw_parts(buf, len) };
            let str = core::str::from_utf8(slice).unwrap();
            print!("{}", str);
            len as isize
        }
        _ => {
            panic!("Unsupported fd in sys_write!");
        }
    }
}
```

exit系统调用在S级的实现：

```rust
// os/src/syscall/process.rs

use crate::batch::run_next_app;

pub fn sys_exit(exit_code: i32) -> ! {
    println!("[kernel] Application exited with code {}", exit_code);
    run_next_app()
}
```

- `sys_write` 我们将传入的位于应用程序内的缓冲区的开始地址和长度转化为一个字符串 `&str` ，然后使用批处理操作系统已经实现的 `print!` 宏打印出来。注意这里我们并没有检查传入参数的安全性，即使会在出错严重的时候 panic，还是会存在安全隐患。这里我们出于实现方便暂且不做修补。
- `sys_exit` 打印退出的应用程序的返回值并调用 `run_next_app` 切换到下一个应用程序。(注意这里，以免看到后续代码时忘记：**我们的批处理系统能运行完所有程序的原因在这里，因为程序调用exit退出时无论返回码是什么，我们的批处理系统都会调用run_next_app来运行下一个程序，直到所有程序都运行完毕**)

### 执行应用程序

当批处理操作系统初始化完成，或者是某个应用程序运行结束或出错的时候，我们要调用 `run_next_app` 函数切换到下一个应用程序。**此时 CPU 运行在 S 特权级，而它希望能够切换到 U 特权级。**在 RISC-V 架构中，唯一一种能够使得 CPU 特权级下降的方法就是执行 Trap 返回的特权指令，如 `sret` 、`mret` 等。事实上，在**从操作系统内核返回到运行应用程序之前**，要完成如下这些工作：

- 构造应用程序开始执行所需的 Trap 上下文；
- 通过 `__restore` 函数，从刚构造的 Trap 上下文中，恢复应用程序执行的部分寄存器；
- 设置 `sepc` CSR的内容为应用程序入口点 `0x80400000`；
- 切换 `scratch` 和 `sp` 寄存器，设置 `sp` 指向应用程序用户栈；
- 执行 `sret` 从 S 特权级切换到 U 特权级。

它们可以通过复用 `__restore` 的代码来更容易的实现上述工作。我们只需要在内核栈上压入一个为启动应用程序而特殊构造的 Trap 上下文，再通过 `__restore` 函数，就能让这些寄存器到达启动应用程序所需要的上下文状态。

为 `TrapContext` 实现 `app_init_context` 方法，修改其中的 sepc 寄存器为应用程序入口点 `entry`， sp 寄存器为我们设定的一个栈指针，并将 sstatus 寄存器的 `SPP` 字段设置为 User 。

```rust
// os/src/trap/context.rs
impl TrapContext {
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }

    // app上下文初始化，此时还处在S特权级
    // 设置sstatus为U特权级
    // 设置sepc指向程序指令的起始地址0x80400000
    // 设置sp指针指向用户栈的栈顶
    // 返回上下文
    pub fn app_init_context(entry: usize, sp: usize) -> Self {
        let mut sstatus = sstatus::read();
        sstatus.set_spp(SPP::User);
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry,
        };
        cx.set_sp(sp: usize);
        cx
    }
}
```

run_next_app()实现如下：

```rust
// 运行下一个app
pub fn run_next_app() -> ! {
    let mut app_manager = APP_MANAGER.exclusive_access();
    let current_app = app_manager.get_current_app();
    unsafe {
        app_manager.load_app(current_app);
    }
    app_manager.move_to_next_app();
    drop(app_manager);
    // before this we have to drop local variables related to resources manually
    // and release the resources
    extern "C" {
        fn __restore(cx_addr: usize);
    }
    unsafe {
        __restore(KERNEL_STACK.push_context(TrapContext::app_init_context(
            APP_BASE_ADDRESS,
            USER_STACK.get_sp(),
        )) as *const _ as usize);
    }
    panic!("Unreachable in batch::run_current_app!");
}
```

在unsafe块所做的事情是在内核栈上压入一个 Trap 上下文，其 `sepc` 是应用程序入口地址 `0x80400000` ，其 `sp` 寄存器指向用户栈，其 `sstatus` 的 `SPP` 字段被设置为 User 。`push_context` 的返回值是内核栈压入 Trap 上下文之后的栈顶，它会被作为 `__restore` 的参数（回看 [__restore 代码](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter2/4trap-handling.html#code-restore) ，这时我们可以理解为何 `__restore` 函数的起始部分会完成 sp←a0 ），这使得在 `__restore` 函数中 `sp` 仍然可以指向内核栈的栈顶。这之后，就和执行一次普通的 `__restore` 函数调用一样了。

```rust
pub fn push_context(&self, cx: TrapContext) -> &'static mut TrapContext {
        let cx_ptr = (self.get_sp() - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe {
            *cx_ptr = cx;
        }
        unsafe { cx_ptr.as_mut().unwrap() }
    }
```

>   同理，操作系统进入S态和内核第一次进入用户态类似，在**M态**的RustSBI中初始化完毕后，将`mstatus.mpp`设置为S态，`mepc`设置为内核入口地址最后通过一条`mret`特权指令让CPU在S模式下执行内核代码。

运行：

![image-20220326190058061](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041733504.png)

可以看到，批处理操作系统已经能够运行使用自己编写的应用程序

## 番外：实现一个能打印调用栈的裸机程序

**待实现**

# 多道程序与分时多任务

>   批处理与多道程序的区别：
> 
>   对于批处理系统而言，它在一段时间内可以处理一批程序，但内存中只放一个程序，处理器一次只能运行一个程序，只有在一个程序运行完毕后再把另外一个程序调入内存，并执行。即批处理系统不能交错执行多个程序。
> 
>   对于支持多道程序的系统而言，它在一段时间内也可以处理一批程序，但内存中可以放多个程序，一个程序在执行过程中，可以主动（协作式）或被动（抢占式）地放弃自己的执行，让另外一个程序执行。即支持多道程序的系统可以交错地执行多个程序，这样系统的利用率会更高。

也就是说，与上一章不同，**应用的编号不再决定其被加载运行的先后顺序，而仅仅能够改变应用被加载到内存中的位置。**

## 多道程序放置与加载

得益于集成电路的快速发展，计算机内存容量越来越大，现在，能够在内存中存放多个应用程序，尽管它们的位置与执行的顺序无关。

### 多道程序放置

由于内存中需要放多个应用程序且执行的顺序不是顺序的，而且我们**目前构建的应用程序都是跟地址有关的**，因此**每个应用程序的起始地址都需要不一样**，而且要**避免不同应用程序重合**。由于**每个程序被加载到的位置都不同**，所以**每个应用程序的链接脚本都不同**。使用python为每个应用定制链接脚本。

脚本的思路如下：

- 第 16~22 行，找到 `src/linker.ld` 中的 `BASE_ADDRESS = 0x80400000;` 这一行，并将后面的地址替换为和当前应用对应的一个地址；
- 第 23 行，使用 `cargo build` 构建当前的应用，注意我们可以使用 `--bin` 参数来只构建某一个应用；
- 第 25~26 行，将 `src/linker.ld` 还原。

```python
# user/build.py

import os

base_address = 0x80400000
step = 0x20000
linker = 'src/linker.ld'

app_id = 0
apps = os.listdir('src/bin')
apps.sort()
for app in apps:
    app = app[:app.find('.')]
lines = []
lines_before = []
with open(linker, 'r') as f:
    for line in f.readlines():
        lines_before.append(line)
    line = line.replace(hex(base_address), hex(base_address + step * app_id))
    lines.append(line)
with open(linker, 'w+') as f:
    f.writelines(lines)
os.system('cargo build --bin %s --release' % app)
print('[build.py] application %s start with address %s' % (app, hex(base_address + step * app_id)))
with open(linker, 'w+') as f:
    f.writelines(lines_before)
app_id = app_id + 1
```

### 多道程序加载

在上一章中，因为所有应用都都要被加载到同一个相同的物理地址0x80400000，因此，内存中最多驻留一个应用，要等这个应用加载完或出错退出的时候再由批处理系统的batch子模块中的run_next_app()来负责加载一个新的应用程序来代替它。本章**所有应用程序在内核初始化的时候就要一并被加载到内存中**，因此需要被加载到不同的物理地址，通过loder子模块的load_apps函数实现：

```rust
use core::arch::asm;
use core::slice::from_raw_parts_mut;

// os/src/loader.rs
use config::*;

use crate::config::{APP_BASE_ADDRESS, APP_SIZE_LIMIT};

// 一次性把内核数据段上的所有应用加载到物理内存中
pub fn load_apps() {
    extern "C" {
        fn _num_app();
    }
    let num_app_ptr = _num_app as usize as *const usize;
    let num_app = get_num_app();
    // app_start指向内核数据段上所有程序指令的开头
    let app_start = unsafe {
        core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1)
    };
    // 清除指令缓存，因为可能需要多次加载所有app到相同的位置并执行
    unsafe {
        asm!("fence.i");
    }
    // 开始一个一个加载
    for i in 0..num_app {
        // 得到第i个程序要加载到的物理内存地址
        let base_i = get_base_i(i);
        // 将要加载程序的地方清空
        (base_i..base_i + APP_SIZE_LIMIT).for_each(|addr| unsafe {
            (addr as *mut u8).write_volatile(0);
        });
        // 把程序从内核的数据段转移到物理内存
        // app_src是第i个程序的切片，长度为程序的大小
        let app_src = unsafe {
            core::slice::from_raw_parts(
                app_start[i] as usize as *const u8,
                app_start[i + 1] - app_start[i],
            )
        };
        // app_dst是第i个程序在物理内存中的位置的切片。长度也为程序的大小
        let app_dst = unsafe {
            core::slice::from_raw_parts_mut(
                base_i as usize as *mut u8,
                app_src.len(),
            )
        };
        app_dst.copy_from_slice(app_src);
    }
}

fn get_num_app() -> usize {
    extern "C" {
        fn _num_app();
    }
    unsafe {
        (_num_app as usize as *const usize).read_volatile()
    }
}

// 返回第i个程序要加载到的物理内存地址
fn get_base_i(app_id: usize) -> usize {
    APP_BASE_ADDRESS + app_id * APP_SIZE_LIMIT
}
```

从这一章开始， `config` 子模块用来存放内核中所有的常数。看到 `APP_BASE_ADDRESS` 被设置为 `0x80400000` ，而 `APP_SIZE_LIMIT` 和上一章一样被设置为 `0x20000` ，也就是每个应用二进制镜像的大小限制。因此，应用的内存布局就很明朗了——就是从 `APP_BASE_ADDRESS` 开始依次为每个应用预留一段空间。这样，我们就说清楚了多个应用是如何被构建和加载的。

## 任务切换

与此前的Trap控制流切换不同，这是另一种异常控制流切换，与此前的Trap切换比较，有以下的不同：

1、此切换不涉及特权级的切换

2、此切换的一部分是由编译器帮忙完成的

当一个应用Trap到S特权级的时候，在其Trap控制流中可调用__switch函数，在此函数返回后，将从调用的地方继续执行下去，调用 `__switch` 之后直到它返回前的这段时间，原 Trap 控制流 *A* 会先被暂停并被切换出去， CPU 转而运行另一个应用在内核中的 Trap 控制流 *B* 。然后在某个合适的时机，原 Trap 控制流 *A* 才会从某一条 Trap 控制流 *C* （很有可能不是它之前切换到的 *B* ）切换回来继续执行并最终返回。

![../_images/task-context.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041734150.png)

当Trap控制流准备调用__switch函数使人物从运行状态进入暂停状态时，发生了如下几件事：

如上图左侧所示，在准备调用 `__switch` 函数之前，内核栈上从栈底到栈顶分别是保存了**应用执行状态的 Trap 上下文**以及**内核在对 Trap 处理的过程中留下的调用栈**信息。由于之后还要恢复回来执行，我们必须保存 CPU 当前的某些寄存器，我们称它们为 **任务上下文** (Task Context)。我们会在稍后介绍里面需要包含哪些寄存器。

至于上下文保存的位置，我们实用数据结构——任务管理器 `TaskManager`来保存 ，在里面能找到一个数组 `tasks` ，其中的**每一项都是一个任务控制块**即 `TaskControlBlock` ，它负责**保存一个任务的状态**，而任务上下文 `TaskContext` 被保存在任务控制块中。

在内核运行时我们会初始化 `TaskManager` 的全局实例 `TASK_MANAGER` ，因此所有任务上下文实际保存在在 `TASK_MANAGER` 中，从内存布局来看则是放在**内核的全局数据 `.data` 段**中。当我们将任务上下文保存完毕之后则转化为下图的状态。当要从其他任务切换回来继续执行这个任务的时候，CPU 会读取同样的位置并从中恢复任务上下文。

对于当前正在执行的任务的 Trap 控制流，我们用一个名为 `current_task_cx_ptr` 的变量来**保存放置当前任务上下文的地址**；而用 `next_task_cx_ptr` 的变量来保存放置下一个要执行任务的上下文的地址。利用 C 语言的引用来描述的话就是：

```
TaskContext *current_task_cx_ptr = &tasks[current].task_cx;
TaskContext *next_task_cx_ptr    = &tasks[next].task_cx;
```

接下来我们同样从栈上内容的角度来看 `__switch` 的整体流程：

![../_images/switch.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041734702.png)

__switch函数需要传入两个参数，第一个参数是current_task_cx_ptr，它指向的是任务控制块中的cx从图中不难发现task_cx是一块保存了对应任务的寄存器状态的一块内存区域。

切换过程可以分为四个阶段，分别是：

- 阶段 [1]：在 Trap 控制流 A 调用 `__switch` 之前，A 的内核栈上只有 Trap 上下文和 Trap 处理函数的调用栈信息，而 B 是之前被切换出去的；
- 阶段 [2]：A 在 A 任务上下文空间在里面保存 CPU 当前的寄存器快照；
- 阶段 [3]：这一步极为关键，读取 `next_task_cx_ptr` 指向的 B 任务上下文，根据 B 任务上下文保存的内容来恢复 `ra` 寄存器、`s0~s11` 寄存器以及 `sp` 寄存器。只有这一步做完后， `__switch` 才能做到一个函数跨两条控制流执行，即 *通过换栈也就实现了控制流的切换* 。
- 阶段 [4]：上一步寄存器恢复完成后，可以看到通过恢复 `sp` 寄存器换到了任务 B 的内核栈上，进而实现了控制流的切换。这就是为什么 `__switch` 能做到一个函数跨两条控制流执行。此后，当 CPU 执行 `ret` 汇编伪指令完成 `__switch` 函数返回后，任务 B 可以从调用 `__switch` 的位置继续向下执行。

实现如下：

```assembly
# os/src/task/switch.S

.altmacro
.macro SAVE_SN n
    sd s\n, (\n+2)*8(a0)
.endm
.macro LOAD_SN n
    ld s\n, (\n+2)*8(a1)
.endm
    .section .text
    .globl __switch
__switch:
    # 阶段 [1]
    # __switch(
    #     current_task_cx_ptr: *mut TaskContext,
    #     next_task_cx_ptr: *const TaskContext
    # )
    # 阶段 [2]
    # save kernel stack of current task
    sd sp, 8(a0)
    # save ra & s0~s11 of current execution
    sd ra, 0(a0)
    .set n, 0
    .rept 12
        SAVE_SN %n
        .set n, n + 1
    .endr
    # 阶段 [3]
    # restore ra & s0~s11 of next execution
    ld ra, 0(a1)
    .set n, 0
    .rept 12
        LOAD_SN %n
        .set n, n + 1
    .endr
    # restore kernel stack of next task
    ld sp, 8(a1)
    # 阶段 [4]
    ret
```

>   RISCV64寄存器是64位宽，一字=4字节=32位，RV64提供了加载和存储双字指令ld和sd
> 
>   sd rs2, offset(rs1)，存双字（64位）指令：将rs2中的8字节（双字）存入内存地址rs1+offset
> 
>   ld rd,offset(rs1)，双字加载指令：从内存rs1+offset处读取8字节（双字），写入rd

阶段一不在此汇编代码中实现，其目的是将两个参数分别放入`a0`和`a1`寄存器

阶段二体现在19-27行，目的是保存A任务的 `ra` 寄存器、`s0~s11` 寄存器以及 `sp` 寄存器。从中我们也能够看出 `TaskContext` 里面究竟包含哪些寄存器：

```rust
// os/src/task/context.rs
pub struct TaskContext {
    ra: usize,
    sp: usize,
    s: [usize; 12],
}
```

为什么阶段二只用保存s0-s11寄存器和ra、sp寄存器，不用保存其他的？

首先保存`ra`很重要（ra是**调用者负责保存的寄存器**），它记录了 `__switch` 函数返回之后应该跳转到哪里继续执行，从而在任务切换完成并 `ret` 之后能到正确的位置。

`s0~s11`是由被调用者（callee）负责保存的寄存器，也就是说对于一般的函数而言，Rust/C编译器会在函数起始位置自动生成代码来保存 `s0~s11` 这些被调用者保存的寄存器。但 `__switch` 是一个用汇编代码写的特殊函数，它不会被 Rust/C 编译器处理，所以我们需要在 `__switch` 中手动编写保存 `s0~s11` 的汇编代码。 

其次保存sp也是必要的，不仅是因为它是需要被调用者保存的寄存器，而且还是函数返回后恢复栈帧的必要参数。

剩下的寄存器，是调用者负责保存的寄存器和无需保存的缓存寄存器（Temporaries），调用switch函数前后编译器会**自动帮我们插入**保存/恢复**调用者保存寄存器**的汇编代码。

阶段三的汇编代码也就很容易理解了。

我们将这段汇编代码中的**全局符号**__switch解释为一个Rust函数：

```rust
// os/src/task/switch.rs
use core::arch::global_asm;
use crate::task::context::TaskContext;

global_asm!(include_str!("switch.S"));

extern "C" {
    pub fn __switch(
        current_task_cx_ptr: *mut TaskContext,
        next_task_cx_ptr: *const TaskContext
    );
}
```

## 多道程序与协作式调度

过去，在CPU对外设发出I/O请求之后，由于CPU速度远快于外设速度，使得 CPU 不能立即继续执行，而是要等待（忙等或睡眠等）外设将请求处理完毕并拿到完整的处理结果之后才能继续。那么如何知道外设是否已经完成了请求呢？通常外设会提供一个可读的寄存器记录它目前的工作状态，于是 CPU 需要不断原地循环读取它直到它的结果显示设备已经将请求处理完毕了，才能继续执行（这就是 **忙等** 的含义）。

然而，外设的计算速度和 CPU 相比可能慢了几个数量级，这就导致 CPU 有大量时间浪费在等待外设这件事情上，这段时间它几乎没有做任何事情，也在一定程度上造成了 CPU 的利用率不够理想。

暂时考虑CPU只能单向地通过读取外设提供的寄存器信息来获取外设处理I/O的状态。多道程序的思想在于：**内核同时管理多个应用**。如果外设处理 I/O 的时间足够长，那我们可以先进行任务切换去执行其他应用；在某次切换回来之后，应用再次读取设备寄存器，发现 I/O 请求已经处理完毕了，那么就可以根据返回的 I/O 结果继续向下执行了。这样的话，只要同时存在的应用足够多，就能一定程度上隐藏 I/O 外设处理相对于 CPU 的延迟，保证 CPU 不必浪费时间在等待外设上，而是几乎一直在进行计算。这种任务切换，是让应用 **主动** 调用 `sys_yield` 系统调用来实现的，这意味着应用主动交出 CPU 的使用权给其他应用。

这就是“协作式”的含义。一个应用会持续运行下去，直到它主动调用 `sys_yield` 系统调用来交出 CPU 使用权。但是这就存在一个缺点：他可能需要等很久才能重新获得CPU的控制权，试想我们敲击了键盘后几分钟后才能在屏幕上看到字符，这是不可忍受的。

sys_yield的标准接口：

```rust
/// 功能：应用主动交出 CPU 所有权并切换到其他应用。
/// 返回值：总是返回 0。
/// syscall ID：124
fn sys_yield() -> isize;
```

我们给出 `sys_yield` 在用户库中对应的实现和封装：

```rust
// user/src/syscall.rs

pub fn sys_yield() -> isize {
    syscall(SYSCALL_YIELD, [0, 0, 0])
}

// user/src/lib.rs

pub fn yield_() -> isize { sys_yield() }
```

注意： `yield` 是 Rust 的关键字，因此我们只能将应用直接调用的接口命名为 `yield_` 。

稍后在内核中实现该系统调用

### 任务运行状态

在第二章批处理系统中我们只需要知道目前执行到第几个应用就行了，因为在一段时间内，内核只管理一个应用。但现在内核需要管理多个未完成的应用，而且我们不能对应用的运行顺序做任何假定，因此，我们必须在内核中对每个应用分别维护它的状态，目前有四种任务运行状态

```rust
// os/src/task/task.rs

#[derive(Copy, Clone, PartialEq)]
pub enum TaskStatus {
    UnInit, // 未初始化
    Ready, // 准备运行
    Running, // 正在运行
    Exited,// 已退出
}
```

>   **Rust Tips：#[derive]**
> 
>   通过 `#[derive(...)]` 可以让编译器为你的类型提供一些 Trait 的默认实现。
> 
> - 实现了 `Clone` Trait 之后就可以调用 `clone` 函数完成拷贝；
> - 实现了 `PartialEq` Trait 之后就可以使用 `==` 运算符比较该类型的两个实例，从逻辑上说只有 两个相等的应用执行状态才会被判为相等，而事实上也确实如此。
> - `Copy` 是一个标记 Trait，决定该类型在按值传参/赋值的时候采用移动语义还是复制语义。

### 任务控制块

```rust
#[derive(Copy, Clone)]
use super::context::TaskContext;
pub struct TaskControlBlock {
    pub task_status: TaskStatus,
    pub task_cx: TaskContext,
}
```

在 `task_cx` 字段中维护了上一小节中提到的任务上下文。任务控制块非常重要，它是内核管理应用的核心数据结构。在后面的章节我们还会不断向里面添加更多内容，从而实现内核对应用更全面的管理。

### 任务管理器

全局的任务管理器将被用来管理这些用任务控制块描述的应用：

```rust
pub struct TaskManager {
    num_app: usize,
    inner: UPSafeCell<TaskManagerInner>,
}

struct TaskManagerInner {
    tasks: [TaskControlBlock; MAX_APP_NUM],
    current_task: usize,
}
```

字段 `num_app` 仍然表示任务管理器管理的应用的数目，它在 `TaskManager` 初始化之后就不会发生变化；而包裹在 `TaskManagerInner` 内的任务控制块数组 `tasks` 以及表示 CPU 正在执行的应用编号 `current_task` 会在执行应用的过程中发生变化：每个应用的运行状态都会发生变化，而 CPU 执行的应用也在不断切换。因此我们需要将 `TaskManagerInner` 包裹在 `UPSafeCell` 内以获取其内部可变性以及单核上安全的运行时借用检查能力。

### 实现 sys_yield 和 sys_exit 系统调用

`sys_yield` 表示应用自己暂时放弃对CPU的当前使用权，进入 `Ready` 状态。其实现用到了 `task` 子模块提供的 `suspend_current_and_run_next` 接口。`sys_exit` 表示应用退出执行。它同样也改成基于 `task` 子模块提供的 `exit_current_and_run_next` 接口，它的含义是退出当前的应用并切换到下个应用。在调用它之前我们打印应用的退出信息并输出它的退出码。如果是应用出错也应该调用该接口，不过我们这里并没有实现，**待实现**。

```rust
// os/src/syscall/process.rs

use crate::task::{exit_current_and_run_next, suspend_current_and_run_next};

pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_exit(exit_code: i32) -> ! {
    println!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}
```

那么 `suspend_current_and_run_next` 和 `exit_current_and_run_next` 各是如何实现的呢？

它们都是先修改当前应用的运行状态，然后尝试切换到下一个应用。

```rust
// os/src/task/mod.rs
pub fn suspend_current_and_run_next() {
    mark_current_suspend();
    run_next_task();
}

pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}
```

以 `mark_current_suspended` 为例。它调用了全局任务管理器 `TASK_MANAGER` 的 `mark_current_suspended` 方法。其中，首先获得里层 `TaskManagerInner` 的可变引用，然后根据其中记录的当前正在执行的应用 ID 对应在任务控制块数组 `tasks` 中修改状态。

```rust
impl TaskManager {
    fn mark_current_suspend(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Ready;
    }

    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Exited;
    }
}
```

接下来看看 `run_next_task` 的实现：

```rust
fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

impl TaskManager {
    fn run_next_task(&self) {
        // find_next_task方法尝试寻找一个运行状态为Ready的应用并返回其id
        // 返回的类型是Option<usize>，因为不一定能找到，找不到返回的是None
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[next].task_status = TaskStatus::Running;
            inner.current_task = next;
            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &mut inner.tasks[next].task_cx as *const TaskContext;
            drop(inner);
            // before this, we should drop local variables that must be dropped manually
            // 必须要手动drop掉，否则不能读写Task_Manager.inner
            unsafe {
                __switch(
                    current_task_cx_ptr,
                    next_task_cx_ptr,
                );
            }
        } else {
            panic!("All applications completed!");
        }
    }
}
```

它会调用 `find_next_task` 方法尝试寻找一个运行状态为 `Ready` 的应用并返回其 ID 。注意到其返回的类型是 `Option<usize>` ，也就是说**不一定能够找到**，当所有的应用都退出并将自身状态修改为 `Exited` 就会出现这种情况，此时 `find_next_task` 应该返回 `None` 。如果能够找到下一个可运行的应用的话，我们就可以分别拿到当前应用 `current_task_cx_ptr` 和即将被切换到的应用 `next_task_cx_ptr` 的任务上下文指针，然后调用 `__switch` 接口进行切换。如果找不到的话，说明所有的应用都运行完毕了，我们可以直接 panic 退出内核。

注意：（第 16 行代码）在实际切换之前我们需要手动 drop 掉我们获取到的 `TaskManagerInner` 的来自 `UPSafeCell` 的借用标记。因为一般情况下它是**在函数退出之后才会被自动释放**，从而 `TASK_MANAGER` 的 `inner` 字段得以**回归到未被借用的状态**，之后可以再借用。如果不手动 drop 的话，编译器会在 `__switch` 返回时，也就是当前应用被切换回来的时候才 drop，这期间我们都不能修改 `TaskManagerInner` ，甚至不能读（因为之前是可变借用），会导致内核 panic 报错退出。正因如此，我们需要在 `__switch` 前提早手动 drop 掉 `inner` 。

那么，方法 `find_next_task` 又是如何实现的呢？

```rust
fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        // tasks是一个固定的任务控制块组成的表，长度为num_app
        // 可以用下标0~num_app-1来访问得到每个应用的控制状态
        // 这里是为了找到current_task后面的第一个状态为Ready的应用
        // 从current_task+1开始循环一圈
        (current + 1..current + self.num_app + 1)
            .map(|id| id % self.num_app)
            .find(|id| {
                inner.tasks[*id].task_status == TaskStatus::Ready
            })
    }
```

`TaskManagerInner` 的 `tasks` 是一个固定的任务控制块组成的表，长度为 `num_app` ，可以用下标 `0~num_app-1` 来访问得到每个应用的控制状态。我们的任务就是找到 `current_task` 后面第一个状态为 `Ready` 的应用。因此从 `current_task + 1` 开始循环一圈，需要首先对 `num_app` 取模得到实际的下标，然后检查它的运行状态。

>   注解
> 
>   `a..b` 实际上表示左闭右开区间 [a,b) ，在 Rust 中，它会被表示为类型 `core::ops::Range` ，标准库中为它实现好了 `Iterator` trait，因此它也是一个迭代器。
> 
>   map：对迭代器的每个项都应用一个闭包
> 
>   find：找到符合闭包中的条件的第一个元素

应用的运行状态变化图如下：

![../_images/fsm-coop.png](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041734829.png)

### 从内核态进入用户态

在应用真正跑起来之前，需要 CPU 第一次从内核态进入用户态。我们上一章批处理系统中进行过类似实现，只需在内核栈上压入构造好的 Trap 上下文，然后 `__restore` 即可。本章的思路大致相同，但是有一些变化。

```rust
// os/src/task/context.rs

impl TaskContext {
    pub fn goto_restore(kstack_ptr: usize) -> Self {
        extern "C" { fn __restore(); }
        Self {
            ra: __restore as usize,
            sp: kstack_ptr,
            s: [0; 12],
        }
    }
}
```

对于每个任务，我们先调用 `init_app_cx` 构造该任务的 Trap 上下文（包括应用入口地址和用户栈指针）并将其压入到内核栈顶。接着调用 `TaskContext::goto_restore` 来构造每个任务保存在任务控制块中的任务上下文。

```rust
// os/src/loader.rs
pub fn init_app_cx(app_id: usize) -> usize {
    KERNEL_STACK[app_id].push_context(
        TrapContext::app_init_context(get_base_i(app_id), USER_STACK[app_id].get_sp()),
    )
}

// os/src/task/mod.rs
for i in 0..num_app {
    tasks[i].task_cx = TaskContext::goto_restore(init_app_cx(i));
    tasks[i].task_status = TaskStatus::Ready;
}
```

它设置任务上下文中的内核栈指针将任务上下文的 `ra` 寄存器设置为 `__restore` 的入口地址。这样，在 `__switch` 从它上面恢复并返回之后就会直接跳转到 `__restore` ，此时栈顶是一个我们构造出来第一次进入用户态执行的 Trap 上下文，就和第二章的情况一样了。

需要注意的是， `__restore` 的实现需要做出变化：它 **不再需要** 在开头 `mv sp, a0` 了。因为在 `__switch` 之后，`sp` 就已经正确指向了我们需要的 Trap 上下文地址。

```assembly
# os/src/trap/trap.S
__restore:
    # restore sstatus/sepc
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    # restore general-purpuse registers except sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # release TrapContext on kernel stack
    addi sp, sp, 34*8
    # now sp->kernel stack, sscratch->user stack
    csrrw sp, sscratch, sp
    sret
```

在上一章，同一时间只有一个程序在运行。只需要一个内核栈和用户栈就行了。上一章中的声明：

```rust
// 原来的os/src/batch.rs，batch.rs已被移除
// KernelStack and UserStack
#[repr(align(4096))]
struct KernelStack {
    data: [u8; KERNEL_STACK_SIZE],
}

#[repr(align(4096))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}

static KERNEL_STACK: KernelStack = KernelStack {
    data: [0; KERNEL_STACK_SIZE],
};
static USER_STACK: UserStack = UserStack {
    data: [0; USER_STACK_SIZE],
};
```

在本章中，每个任务都有自己的内核栈和用户栈了。

```rust
// os/src/loader.rs
static KERNEL_STACK: [KernelStack; MAX_APP_NUM] = [KernelStack {
    data: [0; KERNEL_STACK_SIZE],
}; MAX_APP_NUM];

static USER_STACK: [UserStack; MAX_APP_NUM] = [UserStack {
    data: [0; USER_STACK_SIZE],
}; MAX_APP_NUM];
```

实现UserStack和KernelStack的方法如下：

```rust

```

在 `rust_main` 中我们调用 `task::run_first_task` 来开始应用的执行：

这里我们取出即将最先执行的编号为 0 的应用的任务上下文指针 `next_task_cx_ptr` 并希望能够切换过去。注意 `__switch` 有两个参数分别表示**当前应用和即将切换到的应用的任务上下文指针**，其第一个参数存在的意义是记录当前应用的任务上下文被保存在哪里，也就是当前应用内核栈的栈顶，这样之后才能继续执行该应用。但在 `run_first_task` 的时候，我们**并没有执行任何应用**， `__switch` 前半部分的保存仅仅是在**启动栈（boot stack）**上保存了一些之后不会用到的数据，自然也无需记录启动栈栈顶的位置。

```rust
// os/src/task/mod.rs
fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        let task0 = &mut inner.task[0];
        task0.task_status = TaskStatus::Running;
        let next_task_cx_ptr = &task0.task_cx as *const TaskContext;
        drop(inner);
        let mut _unused = TaskContext::zero_init();
        unsafe {
            __switch(
                &mut _unused as *mut TaskContext,
                next_task_cx_ptr,
            );
        }
        panic!("Unreachable in run_first_task!");
    }

pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}
```

因此，我们显式在启动栈上分配了一个名为 `_unused` 的任务上下文，并将它的地址作为第一个参数传给 `__switch` ，这样保存一些寄存器之后的**启动栈**栈顶的位置将会保存在此变量中。然而无论是此变量还是启动栈我们之后均不会涉及到，一旦应用开始运行，我们就开始在应用的用户栈和内核栈之间开始切换了。这里声明此变量的意义仅仅是为了避免覆盖到其他数据。

现在，操作系统支持把多个应用的代码和数据放置到内存中；并能够执行每个应用；在应用程序发出 `sys_yeild` 系统调用时，能切换应用，从而让 CPU 尽可能忙于每个应用的计算任务，提高了任务调度的灵活性和 CPU 的使用效率。但操作系统中任务调度的主动权在于应用程序的“自觉性”上，操作系统自身缺少强制的任务调度的手段，下一节我们将开始改进这方面的问题。

## 分时多任务系统和抢占式调度

与上一节的**协作式调度**功能不同，本节实现的是**抢占式调度**的功能

协作式调度的特征是：只要一个应用不主动yield交出CPU使用权，它就会一直执行下去。

抢占式调度的特征是：应用随时都有被内核切换出去的可能。现代的任务调度算法基本都是抢占式的，它要求每个引用只能连续执行一段时间，然后内核就会将它强制切换出去，一般将时间片（TimeSlice）作为应用连续执行时长的度量单位，每个时间片可能在毫秒量级。

调度算法需要考虑：每次在换出之前给一个应用多少时间片去执行，以及要换入哪个应用。可以从性能（主要是吞吐量和延迟两个指标）和 **公平性** (Fairness) 两个维度来评价调度算法，后者要求**多个应用分到的时间片占比不应差距过大**。

### 时间片轮转调度

简单起见，我们使用 **时间片轮转算法** (RR, Round-Robin) 来对应用进行调度，只要对它进行少许拓展就能完全满足我们的需求。本章中我们仅需要最原始的 RR 算法，用文字描述的话就是**维护一个任务队列，每次从队头取出一个应用执行一个时间片，然后把它丢到队尾，再继续从队头取出一个应用，以此类推直到所有的应用执行完毕。**

### 与RISC-V中断相关的内容

`sstatus` 的 `sie` 为 **S 特权级**的中断使能，能够同时控制**S特权级下**三种中断，如果将其清零则会将它们全部屏蔽。即使 `sstatus.sie` 置 1 ，还要看 `sie` 这个 CSR，它的三个字段 `ssie/stie/seie` 分别控制 S 特权级的软件中断、时钟中断和外部中断的中断使能。

在此我们只需要了解：

-   **U 特权级的应用程序发出系统调用或产生错误异常都会跳转到 S 特权级的操作系统内核来处理；**
-   **S 特权级的时钟/软件/外部中断产生后，都会跳转到 S 特权级的操作系统内核来处理。**

默认情况下，当中断产生并进入某个特权级之后，在中断处理的过程中**同特权级的中断都会被屏蔽**。中断产生后，硬件会完成如下事务：

-   当中断发生时，`sstatus.sie` 字段会被保存在 `sstatus.spie` 字段中，同时**把 `sstatus.sie` 字段置零**，这样软件在进行后续的中断处理过程中，**所有 S 特权级的中断都会被屏蔽**；
-   当软件执行中断处理完毕后，会执行 `sret` 指令返回到被中断打断的地方继续执行，硬件会**把 `sstatus.sie` 字段恢复为 `sstatus.spie` 字段内的值**。

也就是说，如果不去手动设置 `sstatus` CSR ，在只考虑 S 特权级中断（比如本节的时钟中断）的情况下，是不会出现 **嵌套中断** (Nested Interrupt) 的。嵌套中断是指在处理一个中断的过程中再一次触发了中断。由于默认情况下，在软件开始响应中断前， 硬件会自动禁用所有同特权级中断，自然也就不会再次触发中断导致嵌套中断了。

### 时钟中断与计时器

由于软件（特别是操作系统）需要一种计时机制，RISC-V 架构要求处理器要有一个**内置时钟**，其频率一般低于 CPU 主频。此外，还有一个计数器用来统计处理器自上电以来经过了多少个内置时钟的时钟周期。在 RISC-V 64 架构上，该计数器保存在一个 64 位的 CSR `mtime` 中，我们无需担心它的溢出问题，在内核运行全程可以认为它是一直递增的。

另外一个 64 位的 CSR `mtimecmp` 的作用是：**一旦计数器 `mtime` 的值超过了 `mtimecmp`，就会触发一次时钟中断。**这使得我们可以方便的**通过设置 `mtimecmp` 的值来决定下一次时钟中断何时触发。**

可惜的是，**它们（mtimecmp和mmtime）都是 M 特权级的 CSR** ，而我们的内核处在 S 特权级，是不被允许直接访问它们的。好在运行在 M 特权级的 SEE （这里是RustSBI）已经预留了相应的接口，我们可以调用它们来间接实现**计时器的控制**：

```rust
// os/src/sbi.rs
// RustSBI提供的标准SBI接口，用于设置mtimecmp
pub fn set_timer(timer: usize) {
    sbi_call(SBI_SET_TIMER, timer, 0, 0);
}
```

下面实现timer子模块，`timer` 子模块的 `get_time` 函数可以取得当前 `mtime` 计数器的值，`set_timer` 调用，是一个由 SEE 提供的标准 SBI 接口函数，它可以用来设置 `mtimecmp` 的值。`timer` 子模块的 `set_next_trigger` 函数对 `set_timer` 进行了封装，它首先读取当前 `mtime` 的值，然后计算出每两次中断之间计数器的增量，再将 `mtimecmp` 设置为二者的和。这样，每过一定的时间一个 S 特权级时钟中断就会被触发。

增量的计算方式，常数 `CLOCK_FREQ` 是一个预先获取到的各平台不同的时钟频率，单位为赫兹，也就是一秒钟之内计数器的增量。它可以在 `config` 子模块中找到。`CLOCK_FREQ` 除以常数 `TICKS_PER_SEC` （TICKS_PER_SEC表示每秒产生的中断次数）即是下一次时钟中断的计数器增量值。

我们将一秒钟分为`TICKS_PER_SEC`，也即100个时间片，每个时间片10ms，那么每个时间片内计数器的增量就应该是一秒内的总体增量除以这个整体被分为的份数，所以是`CLOCK_FREQ/100`

```rust
// os/src/timer.rs
use riscv::register::time;
use crate::config::CLOCK_FREQ;
use crate::sbi::set_timer;

// TICKS_PER_SEC表示每秒产生的中断次数
const TICKS_PER_SEC: usize = 100;

// 取得当前mtime计数器的值
pub fn get_time() -> usize {
    time::read()
}

// 设置mtimecmp的值
// CLOCK_FREQ是时钟频率，单位为赫兹，即一秒钟内mtime计数器的增量
// CLOCK_FERQ / TICKS_PER_SEC是下一次时钟中断时计数器的增量值
pub fn set_next_trigger() {
    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
}
```

后面可能还有一些计时的操作，比如统计一个应用的运行时长，我们再设计一个函数：

```rust
// 一秒等于十的六次方微秒
const MICRO_PER_SEC: usize = 1_000_000;

// 以微秒为单位返回当前计数器mtime的值
// CLOCK_FREQ / MICRO_PER_SEC为每微秒内计数器mtime的增量
pub fn get_time_us() -> usize {
    time::read() / (CLOCK_FREQ / MICRO_PER_SEC)
}
```

新增系统调用以获取当前的时间：

```rust
// os/src/syscall/process.rs
use crate::timer::get_time_us;
pub fn sys_get_time() -> isize {
    get_time_us() as isize
}
// os/src/syscall/mod.rs
pub fn syscall(syscall_id: usize, args: [usize; 3]) -> isize {
    match syscall_id {
        SYSCALL_WRITE => sys_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_EXIT => sys_exit(args[0] as i32),
        SYSCALL_YIELD => sys_yield(),
        SYSCALL_GET_TIME => sys_get_time(),
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}
// user/src/syscall.rs
pub fn sys_get_time() -> isize {
    syscall(SYSCALL_GET_TIME, [0, 0, 0])
}
// user/src/lib.rs
pub fn get_time() -> isize {
    sys_get_time()
}
```

### 抢占式调度

```rust
// os/src/syscall/mod.rs
pub fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
    let scause = scause::read();
    let stval = stval::read();
    // 根据 scause 寄存器所保存的 Trap 的原因进行分发处理
    // 这里我们无需手动操作这些 CSR 
    // 而是使用 Rust 的 riscv 库来更加方便的做这些事情。
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        Trap::Exception(Exception::StoreFault) | Trap::Exception(Exception::StorePageFault) => {
            println!("[kernel] PageFault in application, kernel killed it.");
            exit_current_and_run_next();
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            println!("[kernel] IllegalInstruction in application, kernel killed it.");
            exit_current_and_run_next();
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            suspend_current_and_run_next();
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            suspend_current_and_run_next();
        }
        _ => {
            panic!("Unsupported trap {:?}, stval = {:#x}!", scause.cause(), stval);
        }
    }
    cx
}
```

也就是只需在 `trap_handler` 函数下新增一个条件分支跳转，当发现触发了一个 S 特权级时钟中断的时候，首先重新设置mtimecmp，确定下一次中断的时刻，然后调用上一小节提到的 `suspend_current_and_run_next` 函数暂停当前应用并切换到下一个。

```rust
// os/src/main.rs
#[no_mangle]
pub fn rust_main() -> ! {
    clear_bss();
    println!("[kernel] Hello, World!");
    // 先初始化中断向量
    trap::init();
    // 从内核的数据段加载所有应用程序到物理内存
    loader::load_apps();
    // 避免S特权级时钟中断被屏蔽
    trap::enable_timer_interrupt();
    timer::set_next_trigger();
    task::run_first_task();
    panic!("Unreachable in rust_main!");
}
```

那么enable_timer_interrupt是怎么实现的呢？正如前面所述，是通过设置sie.stie是的S特权级时钟中断不会被屏蔽。set_next_trigger设置下一个中断的时刻，也就是10ms后。

```rust
// os/src/trap/mod.rs
use riscv::register::sie;
// 设置sie.stie使S特权级时钟中断不会被屏蔽
pub fn enable_timer_interrupt() {
    unsafe{
        sie::set_stimer();
    }
}
```

这样，**当一个应用运行了 10ms 之后，一个 S 特权级时钟中断就会被触发。**由于应用运行在 U 特权级，且 `sie` 寄存器被正确设置，该中断不会被屏蔽，而是跳转到 S 特权级内的我们的 `trap_handler` 里面进行处理，并顺利切换到下一个应用。这便是我们所期望的抢占式调度机制。从应用运行的结果也可以看出，三个 `power` 系列应用并没有进行 yield ，而是由内核负责公平分配它们执行的时间片。

![image-20220406205709109](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204062057231.png)
