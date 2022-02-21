# Python2中input()函数存在的漏洞及与raw_input()函数的区别

水一篇博客，参考博客：https://blog.51cto.com/u_12332766/2299894

似乎是去年国赛pwn第一题的考点，从操作上来讲利用这个漏洞非常容易

## input()函数产生漏洞的原因

此函数会将stdin输入的内容当做python代码去执行（就像执行计算式一样，将其看做python代码，通过计算返回结果）。如下图：

![image-20210509201005610](https://i.loli.net/2021/05/09/z8QkHVu4RLJiqp3.png)

如果在python中调用系统命令，则可以getshell，如下图：

![image-20210509201113318](https://i.loli.net/2021/05/09/C3PKjW1Gk7Uhole.png)

原文中也举了一例，使用的命令是：

```
__import__('os').system('cat /home/small/flag')
```

去年国赛使用的命令是：

```
__import__('os').system('cat /home/ctf/flag')
```

## input()函数与raw_input()函数的区别

1、 input()函数，能够自动的识别出输入的类型（str,int,fload）
![Python中input()函数漏洞及与raw_input（）函数区别](https://i.loli.net/2021/05/09/h3MlajEGTQXqPJA.png)
raw_input()函数，完全默认为str字符串类型
![Python中input()函数漏洞及与raw_input（）函数区别](https://i.loli.net/2021/05/09/JcvUSCtsRwI7Qmh.png)
2、 input()函数如果接收的是数学计算式，会自动执行得到结果（漏洞产生的原因）
raw_input()函数则会将输入的以字符串形式显示
例：
![Python中input()函数漏洞及与raw_input（）函数区别](https://i.loli.net/2021/05/09/8awonSD5yFzeY3W.png)
输入3+2的字符串，input()函数处理后，得到5；
而raw_input()函数则不会出现这种问题
![Python中input()函数漏洞及与raw_input（）函数区别](https://i.loli.net/2021/05/09/u2PUk7GaZrOCtvw.png)