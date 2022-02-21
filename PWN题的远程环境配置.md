# PWN题的远程环境配置

**仅记录，不作为博客发布**

环境配置参考[如何安全快速地部署多道pwn题目](https://blog.csdn.net/u012763794/article/details/82988934)

总结起来就是：**将pwn题放到bin目录下，回到pwn_deploy_chroot目录下，在root用户下**，先

```
python2 initialize.py
```

运行脚本后会输出每个pwn的监听端口

再启动环境

```
docker-compose up --build -d
```

**下面操作均在root用户下进行**

查看已经下载好的镜像：

```
docker images
```

删除docker中的镜像，我们可以使用如下命令：

```
docker rmi 镜像id
```

删除docker中的容器可以使用如下命令：

```
docker rm 容器id
```

查看所有容器，包括未运行的

```
docker ps -a
```

查看正在运行的

```
docker ps
```

停止正在运行的

```
docker stop 02d356b738ab(容器id)
```

启动停止运行的

```
docker start 02d356b738ab(容器id)
```

重启正在运行的：restart

停止所有容器：

```
docker stop $(docker ps -a -q)
```

删除所有容器：

```
docker rm $(docker ps -a -q)
```

删除所有镜像：

```
docker rmi $(docker images -q)
```

(显然，只停止或删除单个时把后面的变量改为container id即可)

可通过 -f 参数强制删除

```
docker rmi -f $(docker images -q)
```

