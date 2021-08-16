# SecurityInterview
搜集国内安全厂商面试宝典,在求职之路顺风顺水。
## 前言
回想最初进入安全行业时,安全在我的记忆中应该是个小圈子。进入这个圈子前我们缺少途径去真正的了解这个圈子,以及在面试之前我们应该做好哪些技术上的准备. </br>
这些事情能使我们在求职时做好充足准备,万无一失.最早做开发时,有一本《剑指offer》.我最开始的打算是出一本书,但是我意识到这前期需要大量的准备,这也是我打算先在此记录的原因. </br>
我会先将搜集到的面试问题整理于此,回答会在后续一一完善. </br>
我意识到这份事情并不是我一人可以解决的,所以我期望已经在这个圈子里的人士可以贡献自己的一份力量,帮助在求职的别人或将在未来求职的你.
## 字节跳动
    SQL注入
        分类
        手写mysql手注payload（union、报错、延时）
        如何区分后端数据库
        oracle/sqlserver注入
        不同注入场景下注入
            宽字节注入
            二次注入
            order by注入
            limit 注入
            table 名注入
            update/insert 注入
        绕过方式
        getshell
            general_log
            select into dump_file 有什么条件
            站库分离怎么办
        提权
            UDF提权
        防御方式
            使用预编译是否可以防止所有sql注入？
    XSS
        分类（反射、DOM、存储）
            DOM 一定不经过服务器吗？
        防御方式（转义、CSP）
        相关概念（同源策略、Jsonp、CORS）
        利用方式（除盗cookie外）
    CSRF
        防御方式
            使用Referer防御是否一定可靠？
    SSRF
        绕过
            host 绕过
            ip进制绕过
            控制域名解析
            302跳转
            dns rebinding (ttl)
        有回显利用
            端口扫描
            攻击redis
        无回显利用
            dnslog
        防御
    文件上传
        绕过方式
        防御方式
    命令执行
        php
            绕过姿势
            shell_exec和exec的区别
        Java反序列化
            Shiro
