# Novel Dispatch

Novel Dispatch (NDSP) is an innovative web application for fast creation of a HTTP file delivery and sharing system on Windows operating systems.

Novel Dispatch (NDSP) 是一款适用于 Windows 操作系统下快速创建HTTP文件交付和共享系统的网页程序。

![NDSP preview](https://thumbs2.imgbox.com/6c/47/tVkQACQj_t.png)


# Software features / 软件功能

- Map multiple local directories to web-shared buckets.

- User group-based access permission control.

- HTTP direct download or upload link sharing with tokens.

- HTML5-supported multi-threading block-based file uploads.

- UI text, background and color scheme customization.

- API development interface.

- English language support.

---

- 将多个本地目录映射为网页共享文件夹。

- 多用户组权限控制访问。

- 带有令牌的文件HTTP共享直链（支持上传和下载直链）。

- HTML5网页多线程分块上传支持。

- 自定义界面文本、背景及配色方案。

- API开发接口。

- 简体中文语言支持。


# Operate environment / 运行环境

- Windows 10 and above.

- Internet Information Services (IIS) 10.0 with ASP.NET 4.5 and above.

---

- Windows 10 及以上操作系统。

- 带有 ASP.NET 4.5 的 IIS 10.0 及以上版本。


# Installation / 安装说明

Novel Dispatch (NDSP) minimalism deployment instructions

We understand that it might be difficult to get started with a brand new server application, so please follow the essential steps below if you wish to make the application usable in the shortest time.

1. Enable the Internet Information Services (IIS) feature in your Windows operating system. Be sure to enable ASP.NET (Version 4.5) features in the process.

2. Place "default.aspx" in the "C:\inetpub\wwwroot" directory and delete other default files in this directory.

3. Create a directory "C:\ProgramData\Novel Dispatch" and place "config.txt" and "push.html" into this directory.

4. Use Notepad to edit the newly created "config.txt" and replace "D:\" and "E:\" with different paths that eventually exist on the server, for sharing with the users on the network.

Your application should now work by accessing "http://127.0.0.1", and the default login is "admin/admin".

Please note that:

- NDSP permission control is independent of the Windows operating system. For all shared directories, you need to grant access permissions to the "IIS_IUSRS" user group on the Windows operating system side if there is no permission by default.

- NDSP uses the form of user groups for permission control. It is not intended to have too many user groups. If you need an independent user management system, you should create a third-party application with the access to the NDSP API.

- NDSP does not have a built-in file upload client. But we have provided a demo client page "push.html", which also can be used in production environments, for user references.

- You may need to increase the number of working threads in the ASP.NET application pool in IIS settings.


# Changelog / 更新日志

**7.1.1 (2022/11/18)**

1.修复了分享目录存在空格，但无法被正确转义的问题。

---

**7.1.0 (2022/06/20)**

1.优化了服务器侧上传功能的部分设计。

---

**7.0.0 (2022/01/01)**

Novel Dispatch (NDSP)通过全新的架构和设计理念提高Windows操作系统的文件分享体验。

自主研发的新一代基于HTTP协议的C->S免客户端点对点文件上传协议在保留断点续传特性的同时支持多线程并发传输，在连接性较差的网络环境下提高传输效率的同时简化了繁琐的用户上传步骤。

NDSP现拥有独立的配置文件，并以基于用户组的形式提供必要且实用的权限管理功能。

---

**6.0.0 (2021/11/01)**

OurCloud定制版本。

---

**5.1.1 (2021/02/07)**

1.增强Token令牌的AES密钥有效范围和长度，提升系统整体安全性。

---

**5.1.0 (2020/11/14)**

1.Push协议升级为版本6。

2.增加个性化令牌参数，支持"Token","cKey"和"vkey"参数。

3.部分代码优化。

---

**5.0.2 (2020/10/01)**

1.屏蔽115网盘离线下载服务器。

---

**5.0.1 (2020/07/14)**

1.修复了超长文件名会导致界面排版错误的问题。

---

**5.0.0 (2020/06/17)**

1.Push协议升级为版本5。优化后的Push协议将具有更强的兼容性和标准性。

2.增加管理员自定义Token前缀(即IV)的功能。

3.优化部分代码。

---

**4.3.0 (2020/05/10)**

1.删除文件功能改进为使用AJAX交互。

2.增加了一些日志项目。

3.优化部分代码。

---

**4.2.4 (2020/05/09)**

1.新增支持拦截腾讯机器人访问ASP Share服务。

2.修复了一些代码问题。

---

**4.2.2 (2020/03/19)**

1.修复包含方式匹配用户IP地址匹配无效的问题。

---

**4.2.1 (2020/03/18)**

1.增加日志功能，可记录用户请求日志。

2.用户IP地址绑定功能可支持多IP地址及包含匹配。

3.支持生成文件列表页面为文本链接格式。

4.修复在极偶尔的情况下，生成的Token无法被识别的问题。

---

**3.2.0 Client (2020/11/14)**

1.Push协议升级为版本6。

2.增加了自定义上传路径功能。

3.移除了代理设置，程序将自动跟随IE代理设置。

---

**3.1.1 Client (2020/10/02)**

1.优化了一项可能影响传输性能的问题。

---

**3.1.0 Client (2020/07/19)**

1.增加批量开始功能。可批量开始上传多个文件。

2.修复点击工作目录不打开的问题。

---

**3.0.0 Client (2020/07/04)**

1.重新构建程序及代码逻辑，使程序具有更高的稳定性。

2.Push协议升级为版本5。优化后的Push协议将具有更强的兼容性和标准性。

3.更新项目框架至 Microsoft .NET Framework 4.5.2 版本。

4.移除了自定义HTTP代理服务器选项，程序将自动跟随并使用系统代理。
