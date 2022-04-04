# Rust thoughts

主要记录一些初学时的想法与总结

# 1.Cargo.toml和Cargo.lock

你首次构建一个项目的时候，Cargo会输出一个Cargo.lock文件，里面记录了每个库使用的精确的版本。之后构建的时候会直接读取该文件并使用里面的版本。

Cargo只有在你希望它更新的时候才会更新新版本，手动修改Cargo.toml里的版本成新的版本号或者运行cargo update。

cargo update命令仅仅更新最新的兼容版本，如果你想跨不兼容的版本更新，需要手动修改Cargo.toml，下次构建的时候，Cargo会更新版本和Cargo.lock文件。

指定的版本为git仓库的场景，cargo build命令在有Cargo.lock文件的时候不会再拉仓库的最新代码，它会用Cargo.lock里面记录的版本，但是cargo update会拉最新的代码。

Cargo.lock文件是自动生成的，你不应该手动修改它。假如你的项目是一个可执行文件，你应该把Cargo.lock文件提交到代码库，这样，其他人下载构建的时候会使用相同的版本，确保构建后的二进制相同。Cargo.lock文件的修改历史记录了依赖的更新。

假如你的工程是一个普通的库，你不应该把Cargo.lock提交到代码库。你的库的使用者有自己的Cargo.lock文件，它们会忽略你库里的Cargo.lock文件。

假如你的工程是个动态库工程，不会有使用者用到你的源代码，这时也应该提交Cargo.lock文件到代码库。

# 2.引用

>   原文标题: References in Rust
>   原文链接: https://blog.thoughtram.io/references-in-rust/

如果你已经读过我们的文章[Rust’s Ownership](https://link.zhihu.com/?target=https%3A//blog.thoughtram.io/ownership-in-rust/)或者如果你已经写过一些程序并且想知道[what’s the difference between String and &str](https://link.zhihu.com/?target=https%3A//blog.thoughtram.io/string-vs-str-in-rust)，你就应该知道Rust中有个引用的概念。

## 2.1 什么是引用

引用是对内存中的另一个值的非拥有(nonowning)指针类型。引用可以使用借用操作符`&`来创建，所以下面的代码创建了一个变量`x`使其拥有值`10`和一个变量`r`使其引用`x`:

```rust
let x = 10;
let r = &x;
```

因为10是一个原始类型(primitive type)，所以它和引用都存储在栈上。这里是它们在内存中大概的样子（如果你不理解堆和栈这两个术语，你可能需要看一下关于Rust所有权的[那篇文章](https://link.zhihu.com/?target=https%3A//blog.thoughtram.io/ownership-in-rust)）。

```text
				   +–––––-–+
                   │       │
            +–––+––V–+–––+–│–+–––+
stack frame │   │ 10 │   │ • │   │ 
            +–––+––––+–––+–––+–––+
                [––––]   [–––]
                  x        r
```

引用可以指向内存中任何地方的值，不仅仅是栈上的。例如下面的代码，创建了一个之前在[ String vs &str in Rust](https://link.zhihu.com/?target=https%3A//blog.thoughtram.io/string-vs-str-in-rust)中讨论过的字符串切片引用(string slice reference)。

```rust
let my_name = "Pascal Precht".to_string();

let last_name = &my_name[7..];
```

`String`是一个指向存储在堆上的数据的指针类型。**字符串切片(string slice)是数据上子串的引用**，因此它也是指向堆上的内存。

```text
			   my_name       last_name
            [––––––––––––]    [–––––––]
            +–––+––––+––––+–––+–––+–––+
stack frame │ • │ 16 │ 13 │   │ • │ 6 │ 
            +–│–+––––+––––+–––+–│–+–––+
              │                 │
              │                 +–––––––––+
              │                           │
              │                           │
              │                         [–│––––––– str –––––––––]
            +–V–+–––+–––+–––+–––+–––+–––+–V–+–––+–––+–––+–––+–––+–––+–––+–––+
       heap │ P │ a │ s │ c │ a │ l │   │ P │ r │ e │ c │ h │ t │   │   │   │
            +–––+–––+–––+–––+–––+–––+–––+–––+–––+–––+–––+–––+–––+–––+–––+–––+
```

关于字符串，我们还可以创建预分配只读内存的字符串字面量(string literals)。例如下面代码中的`name`就是一个`str`的引用，`str`是存放在程序的预分配内存中的。

```rust
let name = "Pascal";
```

上面的代码看起来像下面这样:

```text
		   name: &str
            [–––––––]
            +–––+–––+
stack frame │ • │ 6 │ 
            +–│–+–––+
              │                 
              +––+                
                 │
 preallocated  +–V–+–––+–––+–––+–––+–––+
 read-only     │ P │ a │ s │ c │ a │ l │
 memory        +–––+–––+–––+–––+–––+–––+
```

关于引用还有什么要讲的呢？还有一些。让我们从共享引用(shared references)和可变引用(mutable reference)开始。

## 2.2 共享引用和可变引用

或许你已经知道，Rust中的变量默认是不可变的。引用也是如此。例如我们有一个`struct Person`并且尝试编译下面的代码:

```rust
struct Person {
  first_name: String,
  last_name: String,
  age: u8
}

let p = Person {
  first_name: "Pascal".to_string(),
  last_name: "Precht".to_string(),
  age: 28
};

let r = &p;

r.age = 29;
```

这会导致一个编译错误:

```text
error[E0594]: cannot assign to `r.age` which is behind a `&` reference
  --> src/main.rs:16:3
   |
14 |   let r = &p;
   |           -- help: consider changing this to be a mutable reference: `&mut p`
15 |   
16 |   r.age = 29;
   |   ^^^^^^^^^^ `r` is a `&` reference, so the data it refers to cannot be written
```

你可以在[这里](https://link.zhihu.com/?target=https%3A//play.rust-lang.org/%3Fversion%3Dstable%26mode%3Ddebug%26edition%3D2018%26gist%3D3a40de737f8c6d47284fe3e91b04598b)进行运行。Rust关于这个问题的处理十分清晰并且它告诉我们可以使用关键字`mut`来使`&p`可变。这对于`r`和`p`也是一样的。但是，这样就引入了另外一个特性，即每次只能有一个可变引用。

```rust
let mut r = &mut p;
let mut r2 = &mut p;
```

上面的代码试图对同一份数据创建两个可变引用。如果我们想要编译这份代码，Rust会报出下面的错误：

```text
error[E0499]: cannot borrow `p` as mutable more than once at a time
  --> src/main.rs:15:16
   |
14 |   let mut r = &mut p;
   |               ------ first mutable borrow occurs here
15 |   let mut r2 = &mut p;
   |                ^^^^^^ second mutable borrow occurs here
16 |   
17 |   r.age = 29;
   |   ---------- first borrow later used here
```

虽然这看上去出乎意料，但是却十分合理。Rust声称是内存安全的，而不能对同一份数据进行多个可变引用便是保证内存安全的条件之一。如果在代码的不同地方存在着多个这样的可变引用，就无法保证它们的其中之一不会以不可预期的方式修改数据。

另一方面，同一份数据有多个共享引用也是有必要的。所以假定`p`和`r`都是不可变的，下面这样做就没有问题:

```rust
let r = &p;
let r2 = &p;
let r3 = &p;
let r4 = &p;
let r5 = &p;
```

对引用进行引用也是有可能的:

```rust
let r = &p;
let rr = &r; // &&p
let rrr = &rr; // &&&p
let rrrr = &rrr; // &&&&p
let rrrrr = &rrrrr; // &&&&&p
```

但是，等等。。。这样符合实际吗？如果我们给一个函数传递一个`r5`，而实际上是一个`&&&&&p`，那个函数将会以什么样的方式接收一个引用的引用的引用的引用的...来工作呢？显然，引用可以被解引用。

## 2.3 解引用

引用可以使用`*`操作符来进行解引用从而获取其在内存中指向的值。如果我们使用前面的代码片段，即`x`拥有值`10`并且`r`引用`x`， 就可以用下面的方式解引用从而进行比较:

```rust
let x = 10;
let r = &x;

if *r == 10 {
  println!("Same!");
}
```

但是，让我们看看一个稍微不同的代码:

```rust
fn main() {
  let x = 10;
  let r = &x;
  let rr = &r; // `rr` is a `&&x`

  if is_ten(rr) {
    println!("Same!");
  }
}

fn is_ten(val: &i32) -> bool {
  *val == 10
}
```

`is_ten()`接收一个`&i32`或者说一个32位有符号整数的引用。尽管实际上我们传递给它的是一个`&&i32`，或者说是一个32位有符号整数的引用的引用。

所以要想让它能够正确运行，似乎`val:&i32`实际上应该是`val:&&i32`，表达式`*val==10`应该是`**val==10`。事实上，如果把代码按照刚刚那样修改确实可以按照预期结果运行。你可以在[这里](https://link.zhihu.com/?target=https%3A//play.rust-lang.org/%3Fversion%3Dstable%26mode%3Ddebug%26edition%3D2018%26gist%3Df03305d9cf51f3d242e989eab4b84019)试试。但是，即使我们没有修改，代码仍然可以正常编译，这里发生了什么？

Rust的比较操作符(例如`==`和`>=`等)是相当智能的，因此只要操作符两边的类型一样，它们可以跟踪一系列的引用直到它们可以找到一个值。这意味着在实际引用中，你可以按照需要进行很多重引用，对于编译器来讲，这些语法开销(syntactical cost)是一样的，因为编译器会替你辨别的。

## 2.4 隐式解引用和借用

此时，你可能想知道，为什么我在具体的类型上调用方法时不需要使用`*`操作符？要想说明这个问题，让我们先来看看之前定义的`Person`结构体:

```rust
struct Person {
  first_name: String,
  last_name: String,
  age: u8
}

fn main() {
  let pascal = Person {
    first_name: "Pascal".to_string(),
    last_name: "Precht".to_string(),
    age: 28
  };

  let r = &pascal;

  println!("Hello, {}!", r.first_name);
}
```

你应该注意到了，即使我们使用的是一个引用，但是我们没有使用`*`操作符也能获取引用`r`里的`first_name`字段。这里我们看到的是Rust编译期的另一个可用性特性(usability feature )。**即`.`操作符会在需要的时候**，进行**隐式的解引用**。

如果没有这个特性的话，可能需要像下面这样写：

```rust
println!("Hello, {}!", (*r).first_name);
```

这也同样适用于借用引用和可变引用。例如，一个数组的`sort()`方法需要一个`&mut self`。但是，当我们像下面这样写时也不需要担心:

```rust
fn main() {
  let mut numbers = [3, 1, 2];
  numbers.sort();
}
```

`.`操作符会隐式地对左边的操作符借用一个引用。这意味着，`.sort()`调用等价于下面的代码：

```rust
(&mut numbers).sort();
```

多么酷!

## 2.5 可变引用与不可变引用

如何在一个作用域里使用同一个可变变量的不可变引用与可变引用

```Rust
fn mut_and_not_mut(){
    let mut s = String::from("Hello Wrold!");
    let s1 = &s;
    let s2 = &s;
    println!("s1:{}\ts2:{}\n",s1,s2);//只要确保下面声明完可变引用后不会再调用上面的不可变引用即可。不过较少发生这种声明完一个变量又不用的情况。
    let s3 = &mut s;
    println!("s3:{}\n",s3);   
}
```

上面代码可以正常执行

```Rust
fn mut_and_not_mut(){
    let mut s = String::from("Hello Wrold!");
    let s1 = &s;
    let s2 = &s;
    println!("s1:{}\ts2:{}\n",s1,s2);
    let s3 = &mut s;		//报错
    println!("s3:{}\n",s3);   
    println!("s1:{}\ts2:{}\n",s1,s2);
}
```

​		结论: 而当你在声明完该变量的可变引用后再一次调用上面声明的不可变引用时编译器就会报错，理由是已经将该变量声明为不可变引用，因此不能同时将它声明为不可变引用。
​		所以，要想在同一个作用域声明不可变引用与可变引用，要保证在声明完可变引用后不会再调用上面声明的不可变引用，否则就会冲突为同时将一个变量声明为可变引用与不可变引用。

​		如果一个可变变量被声明为一个不可变引用，那么也不可以对其进行可变操作（改值）

```rust
fn mut_and_not_mut(){
    let mut s = String::from("Hello Wrold!");
    let s1 = &s;
    let s2 = &s;
    println!("s1:{}\ts2:{}\n",s1,s2);
    s1.push_str("Rust!");		//报错 error[E0596]: cannot borrow `*s1` as mutable, as it is behind a `&` reference
    //编译器提示将上面声明s1的语句改为,let s1 = &mut s; -- help: consider changing this to be a mutable reference: `&mut s`
}
```

```rust
fn mut_and_not_mut(){
    let mut s = String::from("Hello Wrold!");
    let s1 = &s;
    let s2 = &s;
    println!("s1:{}\ts2:{}\n",s1,s2);
    let s3 = &mut s;
    println!("s3:{}\n",s3);   
    s3.push_str("\tRust!");//可以对s3执行.push_str()操作
    //注意这里能调用s3.push_str()并不是说对不可变变量s3进行操作，只是对它指向的s进行push_str()操作。
    println!("s3:{}\n",s3);
}
```

​		验证是否可以对不可变变量进行操作

```rust
fn mut_and_not_mut(){
    let mut s = String::from("Hello Wrold!");
    let mut r = String::from("Python");
    let s1 = &s;
    let s2 = &s;

    println!("s1:{}\ts2:{}\n",s1,s2);
    let  s3 = &mut s;
    println!("s3:{}\n",s3);    
    s3.push_str("\tRust!");
    println!("s3:{}\n",s3);
    s3 = &mut r;//这个是直接对s3进行变化，编译器报错，cannot assign twice to immutable variable,如果要进行这一步操作，需要在声明s3时改成
    //let mut s3 = &mut s;才可以进行s3进行变化操作，即可以指向s，也可以指向r
    
}
```

​		可以将 s3.push_str()看成是*s3.push_str()的语法糖，是编译器自动为我们省去了 *s3 解引用这一步操作（自动解引用）。

# 3.Rust模块系统

>   Cargo 遵循的一个约定：src/main.rs 就是一个与包同名的二进制 crate 的 crate 根。同样的，Cargo 知道如果包目录中包含 src/lib.rs，则包带有与其同名的库 crate，且 src/lib.rs 是 crate 根。
>   如果一个包同时含有 src/main.rs 和 src/lib.rs，则它有两个 crate：一个库和一个二进制项，且名字都与包相同。

看到后我就很快啊，去试了一下，然后就懵了，有些模块系统的规则似乎并不适用于此。

经过一阵探索后，总结规则如下：

-   **crate关键字在不同crate中含义不同。**

在库crate中，代表的是lib.rs；在二进制crate中，代表的是main.rs。

-   **使用自己的crate名代表的是其库crate**

假设crate名为*xxtest*，那么*xxtest::name()*也就是在调用库crate中的函数name。

值得一提的是，自己的crate名在只有在main.rs和lib.rs同时存在的时候才会赋予特殊的含义，并只在二进制crate中可用；

值得二提的是，当存在一个和crate名同名的模块时，会优先调用模块里的东西。

顺带提一嘴，使用mod lib并不能变为一个普通模块，但是你可以使用crate::lib来访问模块了，虽然我并不建议你这么用。

# 4.Use关键字的习惯用法

![image-20220225163052186](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757447.png)

![image-20220225162853596](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757031.png)

![image-20220225162930697](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757932.png)

![image-20220225163104926](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757561.png)

用as起个别名

![image-20220225163201649](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757043.png)

![image-20220225164616519](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757772.png)



![image-20220225164633429](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757164.png)

![image-20220225164741913](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757995.png)

![image-20220225164810211](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757702.png)

![image-20220225165022960](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757623.png)

![image-20220225164901522](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757433.png)

![image-20220225164957360](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757171.png)





# 5.借用和引用

先来看看Rust入门上说的借用与引用：
**我们将获取引用作为函数参数称为 借用（borrowing）**
正如现实生活中，如果一个人拥有某样东西，你可以从他那里借来。当你使用完毕，必须还回去。

## 例子

```rust
fn main() {
	let s1 = String::from("hello");
	let len = calculate_length(&s1);
	println!("The length of '{}' is {}.", s1, len);
}
fn calculate_length(s: &String) -> usize {
	s.len()
}
```

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757012.png)

这里首先创建了一个名字为s1的String，注意不是str，String是可变字符串，由栈里的s1保存指向堆空间的地址，长度以及容量。如上图。

然后调用函数calculate_length，里面传入了一个s1的引用。这里s里存的是s1的引用，也就是说s是一个与s1不同的全新的变量，只是里面存的指针值指向了s1，同时没有长度和容量。这里可以理解为java的引用。

这样做法有一个好处，函数并没有直接获得s1的所有权，当函数结束，即引用离开其作用域s被释放但是s1任然存在并不会被丢弃。所以函数结束后你任然可以继续使用s1。

注意：rust里默认拷贝全是浅拷贝，只会拷贝栈上的引用值，并不会拷贝堆空间的值。

深拷贝可以如下使用：

```rust
let s1 = String::from("hello");
let s2 = s1.clone();
```

## 最后总结

rust借用可以理解为动作，行为，类比a从b那里借东西。
rust引用类似于java的引用，字面上的：&s1。所以我们称
**我们将获取的引用作为函数的参数称为 借用（borrowing）**

# 6.生命周期省略的三原则

**任何引用都有一个生命周期，并且需要为使用引用的函数或结构体指定生命周期参数。**

**函数参数或方法参数中的生命周期被称为输入生命周期(input lifetime), 而返回的生命周期则被称为输出生命周期(output lifetime)。**

在没有显式标注的情况下，编译器目前使用了3种规则来计算引用的生命周期。**第一条规则作用于输入生命周期，第二条和第三条规则作用于输出生命周期。**当编译器检查完这3条规则后仍有无法计算出生命周期的引用时，编译器就会停止运行并抛出错误。**这些规则不但对fn定义生效，也对impl代码块生效。**

**第一条规则是，每一个引用参数都会拥有自己的生命周期参数。**
**第二条规则是，当只存在一个输入生命周期参数时，这个生命周期会被赋予给所有输出生命周期参数。**
**第三条规则是，当拥有多个输入生命周期参数，而其中一个是&self或&mut self时，self的生命周期会被赋予给所有的输出生命周期参数。**

# 7.move、copy、clone和drop

## move语义

rust中的类型，如果没有实现Copy trait，那么在此类型的变量赋值、函数入参、函数返回值都是move语义。这是与c++的最大区别，从c++11开始，右值引用的出现，才有了move语义。但rust天生就是move语义。

如下的代码中，变量a绑定的String实例，被move给了b变量，此后a变量就是不可访问了（编译器会帮助我们检查）。然后b变量绑定的String实例又被move到了f1函数中，，b变量就不可访问了。f1函数对传入的参数做了一定的运算后，再将运算结果返回，这是函数f1的返回值被move到了c变量。在代码结尾时，只有c变量是有效的。

```rust
fn f1(s: String) -> String {s + " world!"}
let a = String::from("Hello");
let b = a;
let c = f1(b);
```

注意，如上的代码中，`String`类型没有实现`Copy` trait，所以在变量传递的过程中，都是move语义。

## copy语义

rust中的类型，如果实现了Copy trait，那么在此类型的变量赋值、函数入参、函数返回值都是copy语义。这也是c++中默认的变量传递语义。

看看类似的代码，变量a绑定的i32实例，被copy给了b变量，此后a、b变量同时有效，并且是两个不同的实例。然后a变量绑定的i32实例又被copy到了f1函数中，a变量仍然有效。传入f1函数的参数i是一个新的实例，做了一定的运算后，再将运算结果返回。这时函数f1的返回值被copy到了c变量，同时f1函数中的运算结果作为临时变量也被销毁（不会调用drop，如果类型实现了Copy trait，就不能有Drop trait）。传入b变量调用f1的过程是相同的，只是返回值被copy给了d变量。在代码结尾时，a、b、c、d变量都是有效的。

```rust
fn f1(i: i32) -> i32 {i + 10}
let a = 1_i32;
let b = a;
let c = f1(a);
let d = f1(b);
```

这里再强调下，`i32`类型实现了`Copy` trait，所以整个变量传递过程，都是copy语义。

## clone语义

move和copy语义都是隐式的，clone需要显式的调用。

参考类似的代码，变量a绑定的String实例，在赋值前先clone了一个新的实例，然后将新实例move给了b变量，此后a、b变量同时有效。然后b变量在传入f1函数前，又clone一个新实例，再将这个新实例move到f1函数中。f1函数对传入的参数做了一定的运算后，再将运算结果返回，这里函数f1的返回值被move到了c变量。在代码结尾时，a、b、c变量都是有效的。

```rust
fn f1(s: String) -> String {s + " world!"}
let a = String::from("Hello");
let b = a.clone();
let c = f1(b.clone());
```

在这个过程中，在隐式move前，变量clone出新实例并将新实例move出去，变量本身保持不变。

## drop语义

rust的类型可以实现Drop trait，也可以不实现Drop trait。但是对于实现了Copy trait的类型，不能实现Drop trait。也就是说Copy和Drop两个trait对同一个类型只能有一个，鱼与熊掌不可兼得。

变量在离开作用范围时，编译器会自动销毁变量，如果变量类型有Drop trait，就先调用Drop::drop方法，做资源清理，一般会回收heap内存等资源，然后再收回变量所占用的stack内存。如果变量没有Drop trait，那就只收回stack内存。

正是由于在Drop::drop方法会做资源清理，所以**Copy和Drop trait只能二选一**。因为如果类型实现了Copy trait，在copy语义中并不会调用Clone::clone方法，不会做deep copy，那就会出现两个变量同时拥有一个资源（比如说是heap内存等），在这两个变量离开作用范围时，会分别调用Drop::drop方法释放资源，这就会出现double free错误。

## copy与clone语义区别

先看看两者的定义：

```rust
pub trait Clone: Sized {
    fn clone(&self) -> Self;
    fn clone_from(&mut self, source: &Self) {
        *self = source.clone()    
	}
}
pub trait Copy: Clone {
    // Empty.
}
```

Clone是Copy的super trait，一个类型要实现Copy就必须先实现Clone。

再留意看，Copy trait中没有任何方法，所以在copy语义中不可以调用用户自定义的资源复制代码，也就是**不可以做deep copy**。**Copy语义就是变量在stack内存的按位复制，没有其他任何多余的操作。**

Clone中有clone方法，用户可以对类型做自定义的资源复制，这就**可以做deep copy**。在clone语义中，类型的Clone::clone方法会被调用，程序员在Clone::clone方法中做资源复制，同时在Clone::clone方法返回时，变量的stack内存也会被按照位复制一份，生成一个完整的新实例。

# 8.Rust 迭代器

## 1、迭代器是什么？

**迭代器**（*iterator*）负责遍历序列中的每一项和决定序列何时结束的逻辑，迭代器是 **惰性的**（*lazy*）。迭代器模式允许你对一个项的序列进行某些处理。

```rust
 let v = vec![1, 2, 3];
 let v_iter = v.iter(); //实际上只是创建了一个迭代器，没有做其他更深层次的动作
```

迭代器使用样例：计算1到10的和

```rust
 fn main() {
     println!("{:?}", (1..10).sum::<i32>());
 }
```

## 2、Iterator trait 和 IntoIterator trait

**迭代器**都实现了定义于标准库的`Iterator trait`（`std::iter::Iterator`)，该trait要求实现其的类型要`impl`关联类型 `Item`与方法`next`，具体可参见定义

```rust
 pub trait Iterator {
     /// The type of the elements being iterated over.
     #[stable(feature = "rust1", since = "1.0.0")]
     type Item;
 
     #[stable(feature = "rust1", since = "1.0.0")]
     fn next(&mut self) -> Option<Self::Item>;
     
     ///一些其他默认实现
 }
```

`Iterator`提供了丰富的`API`及其默认实现，并且其中的默认实现大部分都依赖于`next()`，而`next` 是 `Iterator` 实现者被要求定义的唯一方法。`next` 一次返回迭代器中的一个项，封装在 `Some` 中，当迭代器结束时，它返回 `None`。

标准库中的`IntoIterator trait`定义如下

```rust
 #[rustc_diagnostic_item = "IntoIterator"]
 #[stable(feature = "rust1", since = "1.0.0")]
 pub trait IntoIterator {
     #[stable(feature = "rust1", since = "1.0.0")]
     type Item;
 
     #[stable(feature = "rust1", since = "1.0.0")]
     type IntoIter: Iterator<Item = Self::Item>;
 
     #[stable(feature = "rust1", since = "1.0.0")]
     fn into_iter(self) -> Self::IntoIter;
 }
 
 #[stable(feature = "rust1", since = "1.0.0")]
 impl<I: Iterator> IntoIterator for I {
     type Item = I::Item;
     type IntoIter = I;
 
     fn into_iter(self) -> I {
         self
     }
 }
```

意味着那些实现`Iterator trait`的类型，将自动实现`IntoIterator trait`，于是可以调用`into_iter()`方法，而这也是`for`循环某些类型的工作基础，如下例子

```rust
 fn main() {
     let v = vec![1, 2, 3];
     for i in v {
         println!("{:?}", i);
     }
 }
```

reference说明：A `for` expression is a syntactic construct for looping over elements provided by an implementation of `std::iter::IntoIterator`。

`Iterator`有丰富的API及其默认实现，具体可以参考标准库文档

## 3、迭代器的使用

如果我们注意，就会发现`Iterator trait`的`next`方法的入参为`&mut self`，意味着任何调用了`next`方法的方法都会消耗适配器，这类方法被称为**消费适配器**（`consuming adaptors`），比如前文出现的`sum`方法就是一个**消费**适配器，该方法获取迭代器的所有权并反复调用`next`来遍历迭代器，因而会消费迭代器。

```rust
 fn main() {
     let v = vec![1, 2, 3];
     let mut iter = v.iter();
     println!("{:?}", iter.sum::<i32>());
 }
```

再来看一个`&str`相关的例子，`chars`返回的类型是`Chars`，其实现了`Iterator trait`

```rust
 fn main() {
     let s = "学习迭代器";
     let mut chars = s.chars();
     loop {
         let c = chars.next();
         if c.is_some() {
             println!("{:?}", c.unwrap());
         } else {
             break;
         }
     }
 }
```

可以找到其实现

```rust
 impl<'a> Iterator for Chars<'a> {
     type Item = char;
 
     #[inline]
     fn next(&mut self) -> Option<char> {
         next_code_point(&mut self.iter).map(|ch| {
             // SAFETY: `str` invariant says `ch` is a valid Unicode Scalar Value.
             unsafe { char::from_u32_unchecked(ch) }
         })
     }
 
     #[inline]
     fn count(self) -> usize {
         // length in `char` is equal to the number of non-continuation bytes
         let bytes_len = self.iter.len();
         let mut cont_bytes = 0;
         for &byte in self.iter {
             cont_bytes += utf8_is_cont_byte(byte) as usize;
         }
         bytes_len - cont_bytes
     }
 
     #[inline]
     fn size_hint(&self) -> (usize, Option<usize>) {
         let len = self.iter.len();
         // `(len + 3)` can't overflow, because we know that the `slice::Iter`
         // belongs to a slice in memory which has a maximum length of
         // `isize::MAX` (that's well below `usize::MAX`).
         ((len + 3) / 4, Some(len))
     }
 
     #[inline]
     fn last(mut self) -> Option<char> {
         // No need to go through the entire string.
         self.next_back()
     }
 }
```

`Iterator` trait中定义了另一类方法，被称为**迭代器适配器**（`iterator adaptors`），意味着我们可以将当前的迭代器变为不同类型的迭代器（大部分都是标准库实现的迭代器），又因为`迭代器`是惰性的，必须调用一个消费适配器方法以便获取迭代器适配器调用的结果。

有了**迭代器适配器**之后，我们就可以进行链式调用了（迷之迭代器套娃）

```rust
 fn main() {
     let v = vec![1, 2, 3, 4, 5, 6];
     //s的类型是  Filter<Map<Iter<i32>, ...>, ...>
     let s = v.iter().map(|x| {x + 1}).filter(|x| x % 5 != 0);
     println!("{:?}", s.collect::<Vec<i32>>());  //将打印  2 3 4 6 7
 }
```

观摩一下`fn map`的实现，可以看到Map以当前迭代器作为参数，创造了一个新的`Map`迭代器，

```rust
 pub trait Iterator {    
     ///some code
     
     fn map<B, F>(self, f: F) -> Map<Self, F>
     where
         Self: Sized,
         F: FnMut(Self::Item) -> B,
     {
         Map::new(self, f)
     }
     
     ///some code
 }
 
 ///Map迭代器适配器的实现
 #[must_use = "iterators are lazy and do nothing unless consumed"]
 #[stable(feature = "rust1", since = "1.0.0")]
 #[derive(Clone)]
 pub struct Map<I, F> {
     iter: I,
     f: F,
 }
 impl<I, F> Map<I, F> {
     pub(super) fn new(iter: I, f: F) -> Map<I, F> {
         Map { iter, f }
     }
 }
```

## 4、迭代器适配器与闭包

在**迭代器适配器**中，很多都接受闭包作为其参数参与逻辑实现，即部分**迭代器适配器**拥有捕获环境变量的能力，以`fiter`为例，假如有一份学生名单，需要获取年龄大于指定值的学生

```rust
 #[derive(Debug)]
 struct Student<'a>{
     name: &'a str,
     age: i32,
 }
 
 fn main() {
     let students = vec![
         Student {name: "a", age: 15},
         Student {name: "b", age: 16},
         Student {name: "c", age: 17},
         Student {name: "d", age: 18},
         Student {name: "e", age: 19},
     ];
 
     let min_age = 18;
     let result = students.into_iter().filter(|student| student.age >= min_age).collect::<Vec<Student>>();
     println!("{:?}", result);
     //output -> [Student { name: "d", age: 18 }, Student { name: "e", age: 19 }]
 }
```

## 5、自定义迭代器

通过前面的知识，我们知道，只要给一个类型实现了`Iterator trait`（当然，必须实现`next`方法），就可以在该类型上创建迭代器了，下面例子展示创建了一个斐波那契数列类型上创建迭代器（请注意：这是一个没有终点的迭代器，直到`i32`溢出，如果需要，有可以在`next`方法中去限定终止值）

```rust
 struct Fibonacci {
     x: i32,
     y: i32,
 }
 
 impl Fibonacci {
     fn new() -> Fibonacci {
         Fibonacci {
             x: 0,
             y: 0,
         }
     }
 }
 
 impl Iterator for Fibonacci {
     type Item = i32;
 
     fn next(&mut self) -> Option<Self::Item> {
         if self.x == 0 {
             self.x = 1;
             Some(self.x)
         } else if self.y == 0 {
             self.y = 1;
             Some(self.y)
         } else {
             let s = self.x + self.y;
             self.x = self.y;
             self.y = s;
             Some(s)
         }
     }
 }
 
 
 fn main() {
     let mut f = Fibonacci::new();
     println!("{:?}", f.next());
     println!("{:?}", f.next());
     println!("{:?}", f.next());
     println!("{:?}", f.next());
     println!("{:?}", f.next());
 }
```

## 6、迭代器 VS 循环

迭代器是`Rust`的**零抽象**之一，这意味着迭代器抽象不会引入运行时开销，不会有任何性能上的影响

# 9.Box<T>,Rc<T>,RefCell<T>

![image-20220310160237716](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757762.png)

## 1、作用：

Box<T>：通过Box<T>指针可以在堆上分配数据。

Rc<T>： 通过Rc<T>指针可以共享数据。Rust语言因为有所有权的概念，所以，数据失去了所有权之后，后面就无法使用该数据，而Rc<T>就是解决此类问题的。而Rc<T>指针指向的值是只读性质的，不能够修改。

RefCell<T>：通过RefCell<T>指针可以改变**不可变**的值。Rust一般变量定义为immutable的时候，是不能修改其值的，但是，RefCell<T>指针能做到。

## 2、区别：

1.   Rc<T> 同样的数据有多个拥有者，Box<T> 和 RefCell<T> 同样的数据只有唯一的拥有者；

2.   Box<T>数据的可变或者不可变的借用的检查发生在编译阶段，Rc<T>不可变的借用的检查发生在编译阶段，RefCell<T>不可变或者可变的借用发生在运行阶段

3.   由于RefCell<T>可变借用的检查发生在运行阶段,，即使RefCell<T>定义的是不可变的，你也可以改变RefCell<T>里面定义的值。

## 3、关于弱引用Weak(T)：

1.   弱引用是通过Rc::downgrade传递实例的引用，调用Rc::downgrade会得到Weak(T)类型的智能指针，同时将weak_count加1。
2.   区别在于weak_count无需为0就能使Rc实例被清理，只要strong_count为0就可以了。
3.   可以通过Rc::upgrade方法返回Option<Rc<T>>对象。

## 4、使用弱引用解决循环引用问题

https://zhuanlan.zhihu.com/p/383690146

### 制造循环引用

这里仍然使用前面的例子来试图制造两个相互引用的链表：

```rust
use std::rc::Rc;
use std::cell::RefCell;

#[derive(Debug)]
enum List {
  Cons(i32, RefCell<Rc<List>>),
  Nil
}

impl List {
  // tail方法用来方便地访问Cons成员的第二项
  fn tail(&self) -> Option<&RefCell<Rc<List>>> {
    match self {
      List::Cons(_, item) => Some(item),
      List::Nil => None
    }
  }
}

// 这里在变量a中创建了一个Rc<List>实例来存放初值为5和Nil的List值
let a = Rc::new(List::Cons(5,
  RefCell::new(
    Rc::new(List::Nil)
  )
));

println!("a 初始化后的引用数量 = {}", Rc::strong_count(&a));
// a 初始化后的引用数量 = 1

println!("a 的第二项是 = {:?}", a.tail());
// a 的第二项是 = Some(RefCell { value: Nil })
```

下面在变量b中创建了一个Rc<List>实例来存放初值为10和指向列表a的Rc<List>：

```rust
let b = Rc::new(List::Cons(10,
  RefCell::new(
    Rc::clone(&a)
  )
));

println!("a 在 b 创建后的引用数量 = {}", Rc::strong_count(&a));
// a 在 b 创建后的引用数量 = 2

println!("b 初始化后的引用数量 = {}", Rc::strong_count(&b));
// b 初始化后的引用数量 = 1

println!("b 的第二项是 = {:?}", b.tail());
// b 的第二项是 = Some(RefCell { value: Cons(5, RefCell { value: Nil }) })
```

最后，把a的第二项指向b，造成循环引用：

```rust
if let Some(second) = a.tail() {
  *second.borrow_mut() = Rc::clone(&b);
}

println!("改变a之后，b的引用数量 = {}", Rc::strong_count(&b));
// 改变a之后，b的引用数量 = 2

println!("改变a之后，a的引用数量 = {}", Rc::strong_count(&a));
// 改变a之后，a的引用数量 = 2

println!("a next item = {:?}", a);
// 报错，由于a和b相互引用，所以在打印过程中会无限打印，最终堆栈溢出
```

可以看到将 a 修改为指向 b 之后，a 和 b 中都有的 Rc<List> 实例的引用计数为 2。 在 main 的结尾，rust 会尝试首先丢弃 b，这会使 a 和 b 中 Rc<List> 实例的引用计数减 1。 然而，因为 a 仍然引用 b 中的 Rc<List>，Rc<List> 的引用计数是 1 而不是 0，由于其内存的引用计数为 1，所以 Rc<List> 在堆上的内存不会被丢弃，将会永久保留。

![img](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757648.jpeg)



### 避免引用循环：将 Rc<T> 变为 Weak<T>

我们可以使用弱引用类型Weak<T>来防止循环引用：

```rust
// 引入Weak
use std::rc::{ Rc, Weak };
use std::cell::RefCell;

// 创建树形数据结构：带有子节点的 Node
#[derive(Debug)]
struct Node {
  value: i32,
  parent: RefCell<Weak<Node>>, // 对父节点的引用是弱引用
  children: RefCell<Vec<Rc<Node>>> // 对子节点的引用是强引用
}

// 创建叶子结点
let leaf = Rc::new(Node {
  value: 3,
  children: RefCell::new(vec![]),
  parent: RefCell::new(Weak::new())
});

// 创建枝干节点
let branch = Rc::new(Node {
  value: 5,
  // 将leaf作为branch的子节点
  children: RefCell::new(vec![Rc::clone(&leaf)]),
  parent: RefCell::new(Weak::new())
});
```

使用弱引用连接枝干和叶子节点：

```rust
// 与 Rc::clone 方法类似，
// 使用 Rc::downgrade 方法将leaf节点的父节点使用弱引用指向branch
*(leaf.parent.borrow_mut()) = Rc::downgrade(&branch);

// 使用upgrade方法查看父节点是否存在，返回Option类型，
// 可以成功打印，说明使用弱引用并没有造成循环引用
println!("leaf的parent节点 = {:?}", leaf.parent.borrow().upgrade());
// leaf的parent节点 = Some(Node {
//   value: 5,
//   parent: RefCell { value: (Weak) },
//   children: RefCell {
//     value: [
//       Node {
//         value: 3,
//         parent: RefCell { val (Weak) },
//         children: RefCell { value: [] }
//       }
//     ]
//   }
// })
```

使用 Rc::downgrade 时会得到 Weak<T> 类型的智能指针，每次调用Rc::downgrade 会将 weak_count 加1，用于记录有多少个弱引用，而实例被清理时，关注的是strong_count，只要变成0就会清理，而不关心弱引用 weak_count 的数量。

### 观察 strong_count 和 weak_count 的改变

下面我们使用Rc::strong_count() 和 Rc::weak_count() 方法来观察一下强引用和弱引用的区别，注意他们在作用域销毁时的表现：

```rust
#[derive(Debug)]
struct Node {
  value: i32,
  parent: RefCell<Weak<Node>>,
  children: RefCell<Vec<Rc<Node>>>,
}

let leaf = Rc::new(Node {
  value: 3,
  parent: RefCell::new(Weak::new()),
  children: RefCell::new(vec![]),
});

println!("子节点 强引用 = {}, 弱引用 = {}", Rc::strong_count(&leaf), Rc::weak_count(&leaf));
// 子节点 强引用 = 1, 弱引用 = 0

// 新作用域
{
  let branch = Rc::new(Node {
    value: 5,
    parent: RefCell::new(Weak::new()),
    // leaf放入branch子节点
    children: RefCell::new(vec![Rc::clone(&leaf)]),
  });

  // leaf父节点弱引用branch节点
  *leaf.parent.borrow_mut() = Rc::downgrade(&branch);

  println!("branch 强引用 = {}, 弱引用 = {}", Rc::strong_count(&branch), Rc::weak_count(&branch));
  // branch 强引用 = 1, 弱引用 = 1

  println!("leaf 强引用 = {}, 弱引用 = {}", Rc::strong_count(&leaf), Rc::weak_count(&leaf));
  // leaf 强引用 = 2, 弱引用 = 0
}

println!("leaf 的父节点 = {:?}", leaf.parent.borrow().upgrade());
// leaf 的父节点 = None，上面作用域销毁时，branch强引用从1
// 变成0，注意并不关注弱引用，即使弱引用为1，branch仍将被销毁

println!("leaf 强引用 = {}, 弱引用 = {}", Rc::strong_count(&leaf), Rc::weak_count(&leaf));
// leaf 强引用 = 1, 弱引用 = 0，同样由于上面作用域的销毁，branch对于leaf不再强引用。
```

所以当我们的数据类型有循环引用关系的时候便可以使用Weak<T>类型，使相互引用的数据在指向彼此的同时避免产生循环引用和内存泄漏。

# 10.共享所有权

对任意类型T，Rc是一个指向堆空间T类型并且附上引用计数(计数值也在堆空间上)的指针。克隆Rc类型并不会克隆堆空间上T类型的数据，它只是简单的创建另外一个指针指向它。并把引用计数器加1。当最后一个存在的Rc被释放的时候，堆空间上T类型的数据才释放。一个Rc类型的值可以直接调用T类型的方法。Rc类型的值是不可变的。rust的内存和线程安全保证依赖于变量的使用限制，不能同时是共享的和可变的。Rc变量是共享所有权的，所以不能是可变的。引用计数类型内存管理的一个已知问题是变量相互引用造成都得不到释放引起内存泄露。在rust中造成引用循环需要一个旧值指向一个新值，而旧值需要可变，但是rust的Rc类型为不可变，所以正常情况下不会存在引用循环。然而rust的确存在创建引用循环的方法，如果结合interior mutability和Rc类型，可以创建引用循环导致内存泄露。你可以用std::rc::Weak创建弱引用Rc类型来防止引用循环。

# 11.其他

## 零开销抽象

使用抽象时不会引入额外的运行时开销

例如，使用迭代器，其速度可能可能会比使用for循环更快

## Cargo profile

Cargo内置了dev和release两种profile（配置文件），也可以通过在Cargo.toml中自定义各种配置选项以覆盖默认配置，例如：

![image-20220306141129410](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757558.png)

opt-level：代码优化程度，一般来说优化程度越高，所需的编译时间越长

## Cargo Workspace

![image-20220306144650962](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757323.png)

下面是例子：

![image-20220306144726613](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041757815.png)

先创建空文件夹add和Cargo.toml文件，编辑Cargo.toml

![image-20220306144913003](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041758652.png)

在该文件夹下

```
cargo new adder
```

之后在add目录下

```
cargo build
```

发现出现了target文件夹，生成了Carogo.lock文件，target文件夹用于存放所有成员到的编译产出物，这样做的原因是：工作空间中的各个crate或者项目往往是相互依赖的，如果每个crate都有自己的target目录，那么就不得不反复编译工作空间中各个crate

在add目录下创建一个库crate

```
cargo new add-one --lib
```

![image-20220306145705930](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041758815.png)

为了使adder依赖于add-one crate，需要在adder目录下的Cargo.toml文件中显示指明：

![image-20220306145924526](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041758392.png)

现在可以在adder中使用add-one这个库crate提供的函数了，如下，编译可以通过：

![image-20220306150124824](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041758311.png)

怎么运行adder这个二进制crate呢？

```
cargo run -p adder
```

通过p来指定crate的名称

在创建一个新的库crate：add-two

![image-20220306150659038](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041758817.png)

剩余步骤类似，可在add-two中添加函数

在add-one中添加测试：

![image-20220306150933858](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041758113.png)

在add这个工作空间中执行测试（文件夹下）

```
cargo test
```

会一次性执行所有crate的测试，也可以通过-p指定对某个crate进行单独的测试

