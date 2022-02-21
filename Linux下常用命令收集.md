# Linux下常用命令收集

特开一坑，主要收集使用Kali、Ubuntu时的命令

## 查看当前系统中所有软件包的名字和状态

```
sudo dpkg --get-selections
```

## 卸载程序

```
apt-get remove 软件名
apt-get remove --purge 软件名(删除包，包括删除配置文件等)
apt-get autoremove --purge 软件名(删除包及其依赖的软件包+配置文件等)
```

## 升级三件套

```
sudo apt-get update  // 软件源更新
sudo apt-get full-upgrade  // 升级软件和系统
sudo apt-get clean  // 删除包缓存
```

**apt install update**：将远程软件库和本地软件库做对比，检查哪些软件可以更新，以及软件包依赖关系，给出一个分析报告。只检查不更新。

**apt install upgrade**：在执行upgrade 之前要先执行update ，根据update的分析报告去下载并更新软件。在以下几种情况，某个待升级的软件包不会被升级：

1.新软件包和系统的某个软件包有冲突

2.新软件包有新的依赖，但系统不满足依赖

3.安装新软件包时，要求先移除旧的软件包

**apt install dist-upgrade**：在执行dist-upgrade 之前也要先执行update ，dist-upgrade 包含upgrade，同时增添了以下功能：

1.可以智能处理新软件包的依赖

2.智能冲突解决系统

3.安装新软件包时，可以移除旧软件包，但不是所有软件都可以。

**apt install full-upgrade**：在执行full-upgrade 之前也要先执行update ，升级整个系统，必要时可以移除旧软件包。

## 清理垃圾

```
sudo apt-get autoclean                清理旧版本的软件缓存
sudo apt-get clean                    清理所有软件缓存
sudo apt-get autoremove             删除系统不再使用的孤立软件
```

## 卸载无用内核

```
＃1，首先要使用这个命令查看当前Ubuntu系统使用的内核
uname -a
＃2，再查看所有内核
dpkg --get-selections|grep linux
＃3，删除旧内核和头文件，xxxxx代表内核版本号。下面列出的是可以删除的类型，具体删除还是看步骤二的列出项是啥。
注意：千万不要删除正在运行的内核，即不要删除步骤一列出的内核版本号。
sudo apt-get remove linux-image-xxxxxx-generic
sudo apt-get remove linux-headers-xxxxxx-generic
sudo apt-get remove linux-image-xxxxxx-generic
sudo apt-get remove linux-modules-xxxxxx-generic
sudo apt-get remove linux-modules-extra-xxxxxx-generic
```

## deb软件包的安装与卸载方式

**1. 安装**

dpkg –i 软件包名
如：dpkg –i software-1.2.3-1.deb

**2. 卸载**

dpkg –e 软件名
如：dpkg –e software

**3.查询：查询当前系统安装的软件包：**

dpkg –l 与grep结合使用
