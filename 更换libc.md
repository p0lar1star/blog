# 更换libc

在做 pwn 题时，更换 ELF 文件的 libc 版本一直让人头疼，让程序强行加载特定版本glibc就是我们的目标

## 方法一：pathelf

在 github 上有一个项目叫pathelf，通过这个项目可以实现修改 ELF 中硬编码的 libc 和 ld 的路径。项目地址：https://github.com/NixOS/patchelf

我们通过 patchelf 修改 ELF 文件达到加载指定版本 libc。我们先用 "--set-interpreter" 这个选项来将旧的 ld.so 替换为要加载的 ld.so，然后使用 "--replace-needed" 这个选项将旧的 libc.so 替换成要加载的 libc.so。在使用 "--replace-needed" 时，第 2 个参数是程序原本的动态库的路径，可以由 `ldd $目标文件` 得到，第 3 个参数是新的动态库的路径，第 4 个参数为要修改文件的路径。

通俗的讲，就下面两条命令：

```
patchelf --replace-needed libc.so.6 /glibc/2.27/32/lib/libc.so.6 ./read
patchelf --set-interpreter /glibc/2.27/32/lib/ld-2.27.so ./read
```

## 方法二：free-libc

free-libc是一款用于在单一虚拟机下做不同环境下pwn题的项目，你可以在ubuntu16.04环境下在free-libc的帮助下做其他高版本ubuntu环境下的题目，仅仅需要clibc指令！项目地址：https://github.com/dsyzy/free-libc

## 方法三：利用pwntools，然后gdb附加调试

![更换libc](https://abc.p0lar1s.com/202110282300356.jpg)