# MIPS基础——寄存器与汇编语言

## *Data Types and Literals*

## 数据类型

- 所有MIPS指令都是32位长的
- 各单位：1字节=8位，半字长=2个字节，1字长=4个字节
- 一个字符空间=1个字节
- 一个整型=一个字长=4个字节
- 单个字符用单引号，例如：'b'
- 字符串用双引号，例如："A string"

## *Registers*

## 寄存器

- - - MIPS下一共有32个通用寄存器
    - 在汇编中，寄存器标志由$符开头
    - 寄存器表示可以有两种方式

- - - 直接使用该寄存器对应的编号，例如：从\$0到$31
    - 使用对应的寄存器名称，例如：\$t1, $sp(详细含义，下文有表格)

- - 对于乘法和除法分别有对应的两个寄存器\$lo, $hi

  - - 对于以上二者，不存在直接寻址；必须要通过mfhi("move from hi")以及mflo("move from lo")分别来进行访问对应的内容
    - 栈的走向是从高地址到低地址

MIPS下各个寄存器编号及描述：

| *Register* *Number*寄存器编号 | *Alternative*  *Name*寄存器名 | *Description*寄存器用途                                      |
| ----------------------------- | ----------------------------- | ------------------------------------------------------------ |
| *0*                           | *zero*                        | *the value 0*永远返回零                                      |
| *1*                           | *\$at*                        | *(**a**ssembler **t**emporary) reserved by the assembler*汇编保留寄存器（不可做其他用途） |
| *2-3*                         | *\$v0 - $v1*                  | *(**v**alues) from expression evaluation and function results*存储表达式或者是函数的返回值 |
| *4-7*                         | *\$a0 - $a3*                  | *(**a**rguments) First four parameters for subroutine.* *Not preserved across procedure calls*存储子程序的前4个参数，在子程序调用过程中释放 |
| *8-15*                        | *\$t0 - $t7*                  | *(**t**emporaries) Caller saved if needed. Subroutines can use w/out saving.* *Not preserved across procedure calls*临时变量，同上调用时不保存 |
| *16-23*                       | *\$s0 - $s7*                  | *(**s**aved values) - Callee saved.*  *A subroutine using one of these must save original and restore it before exiting.* *Preserved across procedure calls*调用时保存 |
| *24-25*                       | *\$t8 - $t9*                  | *(**t**emporaries) Caller saved if needed. Subroutines can use w/out saving.* *These are in addition to \$t0 - $t7 above.* *Not preserved across procedure calls.*属性同\$t0~\$t7 |
| *26-27*                       | *\$k0 - $k1*                  | *reserved for use by the interrupt/trap handler*（**K**ernel）仅用于中断函数 |
| *28*                          | *$gp*                         | ***g**lobal **p**ointer.*  *Points to the middle of the 64K block of memory in the static data segment.*指向64k(2^16)大小的静态数据块的中间地址。 |
| *29*                          | *\$sp*                        | ***s**tack **p**ointer*  Points to last location on the stack.栈指针，指向的是栈顶 |
| *30*                          | *\$s8/$fp*                    | ***s**aved value / **f**rame **p**ointer* *Preserved across procedure calls*帧指针 |
| *31*                          | *$ra*                         | ***r**eturn **a**ddress*返回地址                             |

利用gp作基指针，在gp指针32K上下的数据存取，系统只需要一条指令就可完成。如果没有全局指针，存取一个静态数据区域的值需要两条指令：一条是获取由编译器和loader决定好的32位的地 址常量。另外一条是对数据的真正存取。为了使用\$gp, 编译器在编译时刻必须知道一个数据是否在\$gp的64K（上下32k）范围之内。并不是所有的编译和运行系统支持gp的使用。

\$1即\$at，该寄存器为汇编保留 ，由于I型指令的立即数字段只有16位，在加载大常数时，编译器或汇编程序需要把大常数拆开，然后重新组合到寄存器里。比如加载一个32位立即数需要 lui（装入高位立即数）和addi两条指令。像MIPS程序拆散和重装大常数由汇编程序来完成，汇编程序必需一个临时寄存器来重组大常数，这也是为汇编保留$at的原因之一。

## *Program Structure*

## 程序结构

1. 本质其实就只是数据声明+普通文本+程序编码（文件后缀为.s，或者.asm也行）
2. 数据声明在代码段之后（其实在其之前也没啥问题，也更符合高级程序设计的习惯）

### Data

### 数据段

1. 数据段以 **.data**为开始标志
2. 声明变量后，即在主存中分配空间。

### Code

### 代码段

1. 代码段以 **.text**为开始标志
2. 其实就是各项指令操作
3. 程序入口为**main：**标志（这个都一样啦）
4. 程序结束标志（详见下文）

### Comments

### 注释

1. 同C系语言

2. MIPS程序的基本模板如下：

  ```
  # Comment giving name of program and description of function# 说明下程序的目的和作用（其实和高级语言都差不多了）
  # Template.s
  #Bare-bones outline of MIPS assembly language program
  
             .data       # variable declarations follow this line　　　　                # 数据变量声明
                         # ...
  														
             .text       # instructions follow this line	
  		       # 代码段部分															
  main:                  # indicates start of code (first instruction to execute)                       # 主程序
                         # ...
  									
  # End of program, leave a blank line afterwards to make SPIM happy# 必须多给你一行，你才欢？
  ```

## Data Declarations

## 数据声明

format for declarations:

声明的格式：

```
name:	              storage_type	  value(s)	
变量名：（冒号别少了）     数据类型         变量值     
```

- - create storage for variable of specified type with given name and specified value
  - value(s) usually gives initial value(s); for storage type .space, gives number of spaces to be allocated
  - 通常给变量赋一个初始值；对于**.space**,需要指明需要多少大小空间（bytes)

Note: labels always followed by colon ( : )

```
example

var1:		.word	3	# create a single integer variable with initial value 3
						# 声明一个 word 类型的变量 var1, 同时给其赋值为 3
array1:		.byte	'a','b'	# create a 2-element character array with elements initialized
							#   to  a  and  b　　　　　　　　　　　　　　　　　　 
							# 声明一个存储2个字符的数组array1，并赋值 'a', 'b'
array2:		.space	40	# allocate 40 consecutive bytes, with storage uninitialized
						#   could be used as a 40-element character array, or a
						#   10-element integer array; a comment should indicate which!	　　　　　　　　　　　　　　　　　　 
						# 为变量 array2 分配 40字节（bytes)未使用的连续空间，当然，对于这个变量　　　　　　　　　　　　　　　　　　 
						# 到底要存放什么类型的值， 最好事先声明注释下！
msg:		.asciiz "Hello Mips!\n"
```

## Load / Store Instructions

## 加载/保存(读取/写入) 指令集

- 如果要访问内存，不好意思，你只能用 **load** 或者 **store** 指令
- 其他的只能都一律是寄存器操作

load:

```
	lw	register_destination, RAM_source
```

copy word (4 bytes) at source RAM location to destination register.

从内存中 复制 RAM_source 的内容到 对应的寄存器中

（lw中的'w'意为'word',即该数据大小为4个字节）

```
	lb	register_destination, RAM_source
```

copy byte at source RAM location to low-order byte of destination register, and sign-e.g.tend to higher-order bytes

同上， lb 意为 load byte

store word:

```
	sw	register_source, RAM_destination
```

store word in source register into RAM destination

将指定寄存器中的数据 写入 到指定的内存中

```
	sb	register_source, RAM_destination
```

store byte (low-order) in source register into RAM destination

load immediate:

```
	li	register_destination, value
```

\#load immediate value into destination register

顾名思义，这里的 li 意为 load immediate

```
example:
	.data
var1:	.word	23		# declare storage for var1; initial value is 23
　　　　　　　　　　　　　　　# 先声明一个 word 型的变量 var1 = 23;
	.text
__start:
	lw	$t0, var1	# load contents of RAM location into register $t0:  $t0 = var1　　　　　　　　　　　　　　　　　　
					# 令寄存器 $t0 = var1 = 23;
	li	$t1, 5		# $t1 = 5   ("load immediate")　　　　　　　　　　　　　　　　　　 
					# 令寄存器 $t1 = 5;
	sw	$t1, var1	# store contents of register $t1 into RAM:  var1 = $t1　　　　　　　　　　　　　　　　　　 
					# 将var1的值修改为$t1中的值： var1 = $t1 = 5;
	done
```

## Indirect and Based Addressing

## 立即与间接寻址

load address:

**直接给地址**

```
	la	$t0, var1
```

- copy RAM address of var1 (presumably a label defined in the program) into register $t0

indirect addressing:

**地址是寄存器的内容**（可以理解为指针）

```
	lw	$t2, ($t0)
```

- load word at RAM address contained in \$t0 into $t2

```
	sw	$t2, ($t0)
```

- store word in register \$t2 into RAM at address contained in $t0

based or indexed addressing：

**+偏移量**

```
	lw	$t2, 4($t0)
```

- load word at RAM address (\$t0+4) into register $t2
- "4" gives ***offset*** from address in register $t0

```
	sw	$t2, -12($t0)
```

- store word in register \$t2 into RAM at address ($t0 - 12)
- **negative offsets are fine**

Note: based addressing is especially useful for:

不必多说，要用到偏移量的寻址，基本上使用最多的场景无非两种：数组，栈。

- arrays; access elements as offset from base address
- stacks; easy to access elements at offset from stack pointer or frame pointer

```
example：栗子：

		.data
array1:		.space	12		#  declare 12 bytes of storage to hold array of 3 integers　　　　　　　　　　　　　　　　　　　　　　　 
							#  定义一个 12字节 长度的数组 array1, 容纳 3个整型
		.text
__start:	
		la	$t0, array1	#  load base address of array into register $t0　　　　　　　　　　　　　　　　　　　　　　　 
						#  让 $t0 = 数组首地址
		li	$t1, 5		#  $t1 = 5   ("load immediate")
		sw  $t1, ($t0)	#  first array element set to 5; indirect addressing　　　　　　　　　　　　　　　　　　　　　　　　
						# 对于 数组第一个元素赋值 array[0] = $1 = 5
		li $t1, 13		#   $t1 = 13
		sw $t1, 4($t0)	#  second array element set to 13　　　　　　　　　　　　　　　　　　　　　　　　
						# 对于 数组第二个元素赋值 array[1] = $1 = 13 　　　　　　　　　　　　　　　　　　　　　　　　
						# (该数组中每个元素地址相距长度就是自身数据类型长度，即4字节， 所以对于array+4就是array[1])
		li $t1, -7		#   $t1 = -7
		sw $t1, 8($t0)	#  third array element set to -7　　　　　　　　　　　　　　　　　　　　　　　　
						# 同上， array+8 = （address[array[0])+4）+ 4 = address(array[1]) + 4 = address(array[2])
		done
```

## Arithmetic Instructions

## 算术指令集

- 最多3个操作数
- 再说一遍，在这里，**操作数只能是寄存器，绝对不允许出现地址**
- 所有指令统一是32位 = 4 * 8 bit = 4bytes = 1 word

add \$t0,\$t1,\$t2

\$t0 = \$t1 + $t2; add as signed (2's complement) integers

```
		sub		$t2,$t3,$t4	#  $t2 = $t3 - $t4
		addi	$t2,$t3, 5	#  $t2 = $t3 + 5;   "add immediate" (no sub immediate)
		addu	$t1,$t6,$t7	#  $t1 = $t6 + $t7;   add as unsigned integers
		subu	$t1,$t6,$t7	#  $t1 = $t6 + $t7;   subtract as unsigned integers

		mult	$t3,$t4		#  multiply 32-bit quantities in $t3 and $t4, and store 64-bit
							#  result in special registers Lo and Hi:  (Hi,Lo) = $t3 * $t4
							#  运算结果存储在hi,lo（hi高位数据， lo地位数据）
		div	    $t5,$t6		#  Lo = $t5 / $t6   (integer quotient)
							#  Hi = $t5 mod $t6   (remainder)　　　　　　　　　　　　　　　　　　　　　　　　　
							#  商数存放在lo, 余数存放在hi
		mfhi	$t0		#  move quantity in special register Hi to $t0:   $t0 = Hi　　　　　　　　　　　　　　　　　　　　　　　　  
						#  不能直接获取 hi 或 lo中的值， 需要mfhi, mflo指令传值给寄存器
		mflo	$t1		#  move quantity in special register Lo to $t1:   $t1 = Lo
						#  used to get at result of product or quotient
		move	$t2,$t3	#  $t2 = $t3
```

余见：[32位mips指令说明](https://blog.csdn.net/qq_39559641/article/details/89608132)

## Control Structures

## 控制流

Branches

分支（if else系列）

- comparison for conditional branches is built into instruction

```
		b	target			#  unconditional branch to program label target
		beq	$t0,$t1,target	#  branch to target if  $t0 = $t1
		blt	$t0,$t1,target	#  branch to target if  $t0 < $t1
		ble	$t0,$t1,target	#  branch to target if  $t0 <= $t1
		bgt	$t0,$t1,target	#  branch to target if  $t0 > $t1
		bge	$t0,$t1,target	#  branch to target if  $t0 >= $t1
		bne	$t0,$t1,target	#  branch to target if  $t0 <> $t1
```

Jumps

跳转（while, for, goto系列）

```
		j	target	　　　　 #  unconditional jump to program label target
　　　　　　　　　　　　　　　　　　　　　　　    看到就跳， 不用考虑任何条件
		jr	$t3		#  jump to address contained in $t3 ("jump register")
　　　　　　　　　　　　　　　　　　　　　　　　　 类似相对寻址，跳到该寄存器给出的地址处
```

Subroutine Calls

子程序调用

subroutine call: "jump and link" instruction

```
	jal	sub_label	#  "jump and link"
```

- copy program counter (return address) to register $ra (return address register)
- 将当前的程序计数器保存到 $ra 中
- jump to program statement at sub_label

subroutine return: "jump register" instruction

```
	jr	$ra	#  "jump register"
```

- jump to return address in $ra (stored by jal instruction)
- 通过上面保存在  $ra 中的地址返回调用前

Note: return address stored in register $ra; if subroutine will call other subroutines, or is recursive, return address should be copied from $ra onto stack to preserve it, since jal always places return address in this register and hence will overwrite previous value

如果说调用的子程序中有调用了其他子程序，如此往复，则返回地址的标记就用 栈（stack） 来存储, 毕竟 $ra 只有一个，（哥哥我分身乏术啊~~）。

## System Calls and I/O (SPIM Simulator)

##  系统调用 与 输入/输出(主要针对SPIM模拟器）

（本人使用的是Mars 4.4，也通用！)

- 通过系统调用实现终端的输入输出，以及声明程序结束
- 学会使用 ***syscall***
- 参数所使用的寄存器：\$v0，\$a0,  $a1
- 返回值使用： $v0
- 浮点寄存器也称协处理器1（Co-Processor 1 简称CP1）。MIPS 拥有32个浮点寄存器，记为\$f0-$f31

下表给出了系统调用中对应功能，代码，参数机返回值

| Service                               | Code in $v0对应功能的调用码 | Arguments所需参数                                            | Results返回值                                   |
| ------------------------------------- | --------------------------- | ------------------------------------------------------------ | ----------------------------------------------- |
| print_int打印一个整型                 | \$v0 = 1                    | \$a0 = integer to be printed将要打印的整型赋值给 $a0         |                                                 |
| print_float打印一个浮点               | \$v0 = 2                    | \$f12 = float to be printed将要打印的浮点赋值给 $f12         |                                                 |
| print_double打印双精度                | \$v0 = 3                    | \$f12 = double to be printed将要打印的双精度赋值给 $f12      |                                                 |
| print_string                          | \$v0 = 4                    | \$a0 = address of string in memory将要打印的字符串的地址赋值给 $a0 |                                                 |
| read_int                              | \$v0 = 5                    |                                                              | integer returned in \$v0将读取的整型赋值给 $v0  |
| read_float读取浮点                    | \$v0 = 6                    |                                                              | float returned in \$v0将读取的浮点赋值给 $v0    |
| read_double读取双精度                 | \$v0 = 7                    |                                                              | double returned in \$v0将读取的双精度赋值给 $v0 |
| read_string读取字符串                 | \$v0 = 8                    | \$a0 = memory address of string input buffer  将读取的字符串地址赋值给 $a0 $a1 = length of string buffer (n)将读取的字符串长度赋值给 $a1 |                                                 |
| sbrk应该同C中的sbrk()函数动态分配内存 | \$v0 = 9                    | \$a0 = amount需要分配的空间大小（单位目测是字节 bytes）      | address in \$v0将分配好的空间首地址给 $v0       |
| exit退出                              | \$v0 =10                    |                                                              |                                                 |

- - 大概意思是要打印的字符串应该有一个终止符，估计类似C中的'\0', 在这里我们只要声明字符串为 **.asciiz** 类型即可。
  - ![img](https://i.loli.net/2021/09/09/EMyDlWuzKhGBZ3o.png)
  - .ascii 与 .asciiz唯一区别就是 后者会在字符串最后自动加上一个终止符， 仅此而已
  - The read_int, read_float and read_double services read an entire line of input up to and including the newline character.
  - 对于读取整型， 浮点型，双精度的数据操作， 系统会读取一整行，（也就是说以换行符为标志 '\n'）
  - The read_string service has the same semantices as the UNIX library routine fgets.
    - It reads up to n-1 characters into a buffer and terminates the string with a null character.
    - If fewer than n-1 characters are in the current line, it reads up to and including the newline and terminates the string with a null character.
    - 这个不多说了，反正就是输入过长就截取，过短就这样，最后都要加一个终止符。
  - The sbrk service returns the address to a block of memory containing n additional bytes. This would be used for dynamic memory allocation.
  - 上边的表里已经说得很清楚了。
  - The exit service stops a program from running.

```
e.g. Print out integer value contained in register $t2 栗子：打印一个存储在寄存器 $2 里的整型
		li	$v0, 1			# load appropriate system call code into register $v0;
							# 声明需要调用的操作代码为 1 （print_int) 并赋值给 $v0
							# code for printing integer is 1
		move	$a0, $t2	# move integer to be printed into $a0:  $a0 = $t2
							# 将要打印的整型赋值给 $a0
		syscall				# call operating system to perform operation
e.g.   Read integer value, store in RAM location with label int_value (presumably declared in data section)栗子：读取一个数，并且存储到内存中的 int_value 变量中
		li	$v0, 5			# load appropriate system call code into register $v0;
							# code for reading integer is 5　　　　　　　　　　　　　　　　　　　　　　　　　　　　　
							# 声明需要调用的操作代码为 5 （read_int) 并赋值给 $v0　
		syscall				# call operating system to perform operation
							# 经过读取操作后， $v0 的值已经变成了 输入的 5
		sw	$v0, int_value	# value read from keyboard returned in register $v0;
							# store this in desired location
							# 通过写入（store_word)指令 将 $v0的值（5） 存入 内存中　　　　　　　　　
e.g.   Print out string (useful for prompts)栗子：打印一个字符串(这是完整的，其实上面栗子都可以直接替换main: 部分，都能直接运行)
		.data
string1:		.asciiz	"Print this.\n"		# declaration for string variable, 
										# .asciiz directive makes string null terminated

		.text
main:		li	$v0, 4			# load appropriate system call code into register $v0;
								# code for printing string is 4
								# 打印字符串， 赋值对应的操作代码 $v0 = 4
		la	$a0, string1		# load address of string to be printed into $a0
								# 将要打印的字符串地址赋值  $a0 = address(string1)
		syscall					# call operating system to perform print operation

e.g. To indicate end of program, use exit system call
;thus last lines of program should be:执行到这里， 程序结束， 立马走人， 管他后边洪水滔天~~

		li	$v0, 10				# system call code for exit = 10
		syscall					# call operating sys
```

## 浮点寄存器

每个浮点寄存器为64位。这32个浮点寄存器在使用约定（ABI）上和通用寄存器一样，也有自己一套说明。如下所示：

| 浮点寄存器编号              | 功能简介       |
| --------------------------- | -------------- |
| \$f0,$f2                    | 用作函数返回值 |
| \$f12 - $f19                | 用作传递参数   |
| \$f24 - $f31                | 寄存器变量     |
| \$f1,\$f3-\$f11,\$f20-\$f23 | 用作临时变量   |

发生函数调用时要保存功能的分配基本上和通用寄存器相同。**比如一个函数返回值为整数或指针时，使用通用寄存器的v0，返回值为浮点类型时，就使用浮点寄存器f0**。**函数调用时的参数是整型就用通用寄存器a0-a7传递，如果是浮点类型就用\$f12-\$f19传递**。对于函数返回地址、栈指针等还是使用通用寄存器的ra、sp。

比如我们要实现两个浮点数的加法运算，用c语言实现就是：

```
float c = fa+fb;
```

同样的功能，对应的汇编指令如下：

```
add.s $f0, $f0, $f1
```

指令add.s实现的是对两个浮点寄存器的加法操作。上面的“add.s \$f0, \$f0,\$f1 ” 意思是浮点寄存器\$f1和\$f0相加，结果存入\$f0的运算。由于浮点运算的性能和功耗会低于整数，平时使用又不是很多，所以浮点寄存器的使用不做展开介绍，阅读mips汇编代码时能认出浮点寄存器就可以了。

## 环境搭建

详见以前的博客
