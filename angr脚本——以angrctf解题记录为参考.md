# angr脚本——angrctf解题记录

​		angr是用于逆向工程中进行二进制分析的一个python框架

​		符号执行 （Symbolic Execution）是一种程序分析技术。其可以通过分析程序来得到让特定代码区域执行的输入。使用符号执行分析一个程序时，该程序会使用符号值作为输入，而非一般执行程序时使用的具体值。在达到目标代码时，分析器可以得到相应的路径约束，然后通过约束求解器来得到可以触发目标代码的具体值。

​		以下脚本均用Python3执行，在笔者Ubuntu16.04虚拟机上通过，且能够得到正确的结果

## 0x00.白给题，简单脚本

```
import angr

p = angr.Project("./00_angr_find")
init_state = p.factory.entry_state()
sm = p.factory.simulation_manager(init_state)
sm.explore(find=0x08048678)  # 输出GoodJob的地方
found_state = sm.found[0]
found_state.posix.dumps(0)  # 标准输入
```



## 0x01.增加限制条件——explore函数中find和avoid的使用

```
import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  # Explore the binary, but this time, instead of only looking for a state that
  # reaches the print_good_address, also find a state that does not reach 
  # will_not_succeed_address. The binary is pretty large, to save you some time,
  # everything you will need to look at is near the beginning of the address 
  # space.
  # (!)
  print_good_address = 0x080485e5
  will_not_succeed_address = 0x080485a8
  simulation.explore(find=print_good_address, avoid=will_not_succeed_address)

  if simulation.found:
    solution_state = simulation.found[0]
    print (solution_state.posix.dumps(0))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

## 0x02.find和avoid的进一步使用——以输出作为限制条件

```
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  # Define a function that checks if you have found the state you are looking
  # for.
  def is_successful(state):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = state.posix.dumps(1)

    # Return whether 'Good Job.' has been printed yet.
    # (!)
    return b'Good Job.' in stdout_output  # :boolean

  # Same as above, but this time check if the state should abort. If you return
  # False, Angr will continue to step the state. In this specific challenge, the
  # only time at which you will know you should abort is when the program prints
  # "Try again."
  def should_abort(state):
    stdout_output = state.posix.dumps(1)
    return b'Try again.' in stdout_output  # :boolean

  # Tell Angr to explore the binary and find any state that is_successful identfies
  # as a successful state by returning True.
  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(0))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

## 0x03.寄存器符号化

```
import angr
import sys
import claripy


def main(argv):
    bin_path = argv[1]
    p = angr.Project(bin_path)  # 执行前的初始化工作，例如生成中间语言等

    start_addr = 0x80488d1  # 指定程序入口地址
    init_state = p.factory.blank_state(addr=start_addr)

    pass1 = claripy.BVS('pass1', 32)  # 生成符号向量，前者为名称，后者为32/64位
    pass2 = claripy.BVS('pass2', 32)
    pass3 = claripy.BVS('pass3', 32)

    init_state.regs.eax = pass1  # 设置初始状态时各寄存器的状态
    init_state.regs.ebx = pass2
    init_state.regs.edx = pass3

    sm = p.factory.simulation_manager(init_state)  # 开始模拟执行

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)  # 寻找结果

    if sm.found:
        found_state = sm.found[0]

        password1 = found_state.solver.eval(pass1)  # 求出结果
        password2 = found_state.solver.eval(pass2)
        password3 = found_state.solver.eval(pass3)
        print("Solution: {:x} {:x} {:x}".format(password1, password2, password3))
    else:
        raise Exception("No solution found")


if __name__ == '__main__':
    main(sys.argv)
```

## 0x04.栈符号化

```
import angr
import sys
import claripy


def main(argv):
    bin_path = argv[1]
    p = angr.Project(bin_path)  # 执行前的初始化工作，例如生成中间语言等

    start_addr = 0x8048697  # 指定程序入口地址
    init_state = p.factory.blank_state(addr=start_addr)  # 初始化状态

    pass1 = claripy.BVS('pass1', 32)  # 生成符号向量，前者为名称，后者为32/64位
    pass2 = claripy.BVS('pass2', 32)
    # 对栈的模拟
    #            /-------- The stack --------\
    # ebp ->     |          padding          |
    #            |---------------------------|
    # ebp - 0x01 |       more padding        |
    #            |---------------------------|
    # ebp - 0x02 |     even more padding     |
    #            |---------------------------|
    #                        . . .               <- How much padding? Hint: how
    #            |---------------------------|      many bytes is password0?
    # ebp - 0x0b |   password0, second byte  |
    #            |---------------------------|
    # ebp - 0x0c |   password0, first byte   |
    #            |---------------------------|
    # ebp - 0x0d |   password1, last byte    |
    #            |---------------------------|
    #                        . . .
    #            |---------------------------|
    # ebp - 0x10 |   password1, first byte   |
    #            |---------------------------|
    #                        . . .
    #            |---------------------------|
    # esp ->     |                           |
    #            \---------------------------/
    #

    padding_size = 8  # 栈中填充的长度,即输入的内容入栈时esp=ebp-0x08
    # 对栈的情况进行模拟
    # ebp是父ebp，保存完父函数ebp才开辟本函数栈空间，当函数执行完以后会有一个pop ebp恢复父函数ebp
    # 但是因为我们要执行的代码与父函数无关，只用执行到find的地方就可以了，不用返回父函数接着执行，所以保存不保存父函数ebp都无所谓
    # 即：ebp是上一个栈桢的栈基,在这个函数里,这个ebp的值是未知的,在这个angr程序里不会执行到在函数最后几条指令的pop ebp,自然也就不需要再push ebp
    init_state.regs.ebp = init_state.regs.esp
    init_state.regs.esp -= padding_size
    # 模拟scanf的入栈过程
    init_state.stack_push(pass1)
    init_state.stack_push(pass2)

    sm = p.factory.simulation_manager(init_state)  # 开始模拟执行

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)  # 寻找结果

    if sm.found:
        found_state = sm.found[0]

        password1 = found_state.solver.eval(pass1)  # 求出结果
        password2 = found_state.solver.eval(pass2)
        print("Solution: {} {}".format(password1, password2))
    else:
        raise Exception("No solution found")


if __name__ == '__main__':
    main(sys.argv)
```

## 0x05.静态内存符号化

```
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048606
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 8*8)
  password1 = claripy.BVS('password1', 8*8)
  password2 = claripy.BVS('password2', 8*8)
  password3 = claripy.BVS('password3', 8*8)

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)
  password0_address = 0xa29faa0
  initial_state.memory.store(password0_address, password0)
  password1_address = 0xa29faa8
  initial_state.memory.store(password1_address, password1)
  password2_address = 0xa29fab0
  initial_state.memory.store(password2_address, password2)
  password3_address = 0xa29fab8
  initial_state.memory.store(password3_address, password3)


  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job.' in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try again.' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=str
    # which returns a string instead of an integer.
    # (!)
    solution0 = solution_state.se.eval(password0,cast_to=bytes).decode("utf-8")
    solution1 = solution_state.se.eval(password1,cast_to=bytes).decode("utf-8")
    solution2 = solution_state.se.eval(password2,cast_to=bytes).decode("utf-8")
    solution3 = solution_state.se.eval(password3,cast_to=bytes).decode("utf-8")

    solution = ' '.join([ solution0, solution1, solution2, solution3 ])

    print (solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

## 0x06.动态内存符号化

```
# malloc出来的内存地址是不确定的，但是，我们可以跳过malloc和scanf，给指针变量buffer一个指定的内存地址
import angr
import sys
import claripy


def main(argv):
    bin_path = argv[1]
    p = angr.Project(bin_path)

    start_address = 0x0804869E  # 跳过malloc和scanf
    init_state = p.factory.blank_state(addr=start_address)
    buffer0 = 0x44444444  # 随便指定两块内存地址,存放符号化向量
    buffer1 = 0x44444544
    buffer0_addr = 0xa79a118  # 指向这两块内存地址的指针，存放他们的地址
    buffer1_addr = 0xa79a120
    # Note: by default, Angr stores integers in memory with big-endianness. To
    # specify to use the endianness of your architecture, use the parameter
    # endness=project.arch.memory_endness. On x86, this is little-endian.
    # (!)
    # 内存中的内容是小端序的，故要加上参数endness = p.arch.memory_endness,否则写入的地址是大端序的
    init_state.memory.store(buffer0_addr, buffer0, endness=p.arch.memory_endness)
    init_state.memory.store(buffer1_addr, buffer1, endness=p.arch.memory_endness)
    # 存入符号向量
    p0 = claripy.BVS('p0', 64)
    p1 = claripy.BVS('p1', 64)
    init_state.memory.store(buffer0, p0)
    init_state.memory.store(buffer1, p1)

    sm = p.factory.simulation_manager(init_state)

    def is_successful(state):
        return b'Good Job.' in state.posix.dumps(1)

    def should_abort(state):
        return b'Try again.' in state.posix.dumps(1)

    sm.explore(find=is_successful, avoid=should_abort)

    if sm.found:
        solution = sm.found[0]
        pass0 = solution.se.eval(p0, cast_to=bytes).decode("utf-8")
        pass1 = solution.se.eval(p1, cast_to=bytes).decode("utf-8")
        print("Solution: {} {}".format(pass0, pass1))
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)
```

## 0x07.文件符号化

```
import angr
import sys
import claripy


def main(argv):
    bin_path = argv[1]
    p = angr.Project(bin_path)
    # 从scanf及ignore_me后，memset前开始执行
    start_addr = 0x80488de
    init_state = p.factory.blank_state(addr=start_addr)

    filename = "WCEXPXBW.txt"
    filesize = 0x40
    # 构造符号向量
    password = init_state.solver.BVS("password", filesize*8)
    # 构造符号化文件,SimFile函数用于构造文件信息，包括文件名，文件内容和文件大小
    sim_file = angr.storage.SimFile(filename, content=password, size=filesize)
    # 将符号化文件插入到初始状态中,angr.fs.insert是将文件插入到文件系统中，需要文件名与符号化的文件
    init_state.fs.insert(filename, sim_file)
    sm = p.factory.simgr(init_state)

    def is_successful(state):
        return b'Good Job.' in state.posix.dumps(1)

    def should_abort(state):
        return b'Try again.' in state.posix.dumps(1)

    sm.explore(find=is_successful, avoid=should_abort)

    if sm.found:
        solution = sm.found[0]
        password_str = solution.solver.eval(password, cast_to=bytes).decode("utf-8")
        print("Solution: {} ".format(password_str))
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    main(sys.argv)
```

## 0x08.增加约束条件解决路径爆炸问题

```
import angr
import sys
def main(argv):
    bin_path = argv[1]
    p = angr.Project(bin_path)

    start_addr = 0x0804862A
    init_state = p.factory.blank_state(addr=start_addr)
    
    buffer_addr = 0x0804A050
    password = init_state.solver.BVS("password", 16*8)
    init_state.memory.store(buffer_addr, password)
    
    sm = p.factory.simgr(init_state)
    
    check_addr = 0x08048565#此地址并非调用call check的地址，而是点进去看到的函数的代码段的起始地址
    sm.explore(find=check_addr)#寻找各种到此函数的路径
    if sm.found:
        check_state = sm.found[0]
        desired_string = "BWYRUBQCMVSBRGFU"
        check_param1 = buffer_addr
        check_param2 = 0x10
        #从内存中把经过变化的buffer再取出来，进行后一步比较
        check_bvs = check_state.memory.load(check_param1, check_param2)
        check_constraint = desired_string == check_bvs
        check_state.add_constraints(check_constraint)
        password1 = check_state.solver.eval(password, cast_to=bytes).decode("utf-8")
        print("Solution: {}".format(password1))
        
if __name__ == '__main__':
    main(sys.argv)
```

## 0x09.设置hook函数解决路径爆炸问题

```
import angr
import sys
import claripy

def main(argv):
    bin_path = argv[1]
    p = angr.Project(bin_path)
    init_state = p.factory.entry_state()#从main函数开始，angr自动帮你处理输入
    # Hook the address of where check_equals_ is called.
    # (!)
    check_addr = 0x080486B8#call check_equals这条指令的位置
    check_skip_size = 5#
    #自定义hook函数
    @p.hook(check_addr, length = check_skip_size)#先指定call hook函数的位置，再指定call hook函数这条指令的大小
    def check_hook(state):
        user_input_addr = 0x0804A054
        user_input_length = 16
        user_input_bvs = state.memory.load(user_input_addr, user_input_length)#从指定的位置取出输入
        desired_string = "XKSPZSJKJYQCQXZV"#我们想要的字符串
        #hook函数的返回，返回值给到eax
        state.regs.eax = claripy.If(desired_string == user_input_bvs, claripy.BVV(1, 32), claripy.BVV(0, 32))
        
    def is_good(state):
        return b'Good Job.' in state.posix.dumps(1)
    def is_bad(state):
        return b'Try again.' in state.posix.dumps(1)
    
    sm = p.factory.simgr(init_state)
    sm.explore(find=is_good, avoid=is_bad)
    
    if sm.found:
        found_state = sm.found[0]
        
        print("Solution: {}".format(found_state.posix.dumps(0)))
    else:
        raise Exception("Solution Not found")

if __name__ == '__main__':
    main(sys.argv)
```

## 0x0A.hook所有同名函数

```
import angr
import sys
import claripy

def main(argv):
    bin_path = argv[1]
    p = angr.Project(bin_path)
    
    init_state = p.factory.entry_state()
    #将hook函数设置成一个类
    class mySimPro(angr.SimProcedure):
        def run(self, to_check, length):#传入用户输入的地址和输入长度
            user_input_buffer_address = to_check
            user_input_buffer_length = length
            angr_bvs = self.state.memory.load(user_input_buffer_address, user_input_buffer_length)#让angr从内存中把输入的东西提取出来
            desired = 'WQNDNKKWAWOLXBAC'
            return claripy.If(desired == angr_bvs, claripy.BVV(1, 32), claripy.BVV(0, 32))
            
    check_symbol = "check_equals_WQNDNKKWAWOLXBAC"#函数名称
    p.hook_symbol(check_symbol, mySimPro())
    
    sm = p.factory.simgr(init_state)
    
    def is_good(state):
        return b"Good Job" in state.posix.dumps(1)
    def is_bad(state):
        return b"Try again" in state.posix.dumps(1)
    sm.explore(find=is_good, avoid=is_bad)
      
    if sm.found:
        found_state = sm.found[0]
        password = found_state.posix.dumps(0)
        print("Solution: {}".format(password.decode("utf-8")))
    else:
        raise Exception("Solution not found")
    
if __name__ == '__main__':
    main(sys.argv)
```