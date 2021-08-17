# SecurityInterview
搜集国内安全厂商面试宝典,在求职之路顺风顺水。
## 前言
回想最初进入安全行业时,安全在我的记忆中应该是个小圈子。进入这个圈子前我们缺少途径去真正的了解这个圈子,以及在面试之前我们应该做好哪些技术上的准备. </br>
这些事情能使我们在求职时做好充足准备,万无一失.最早做开发时,有一本《剑指offer》.我最开始的打算是出一本书,但是我意识到这前期需要大量的准备,这也是我打算先在此记录的原因. </br>
我会先将搜集到的面试问题整理于此,回答会在后续一一完善. </br>
做这件事情的核心思想:搜集这些面试题意欲为何？并非是想让应试者死记硬背其中的知识点,渗透是一个实操为主的行业,死记硬背只会让在入职后无法在企业中无法立足.初衷在于给读者指明学习的方向,还有让读者知道和企业要求的差距,第三点为让读者做好准备. </br>
我意识到这份事情并不是我一人可以解决的,所以我期望已经在这个圈子里的人士可以贡献自己的一份力量,帮助在求职的别人或将在未来求职的你.
## 字节跳动
    SQL注入
        1.SQL注入的分类
            答:按照参数类型分为1.字符型 2.数字型注入
               按照注入位置分为1.get 2.post
               按照sql语法分为1.union注入 2.boolean注入 3.报错注入 4.时间注入 5.堆叠注入 6.宽字节注入
               参考地址:https://www.cnblogs.com/-chenxs/p/11614129.html
        2.手写mysql手注payload（union、报错、延时）
            
        3.如何区分后端数据库
        4.oracle/sqlserver注入
        5.不同注入场景下注入
            宽字节注入
            二次注入
            order by注入
            limit 注入
            table 名注入
            update/insert 注入
        6.sql注入遇到waf时的绕过手法
        7.getshell
            general_log
            select into dump_file 有什么条件
            站库分离怎么办
        8.提权
            UDF提权
        9.防御方式
            使用预编译是否可以防止所有sql注入？
    XSS
        10.分类（反射、DOM、存储）
            DOM 一定不经过服务器吗？
        11.防御方式（转义、CSP）
        12.相关概念（同源策略、Jsonp、CORS）
        13.利用方式（除盗cookie外）
    CSRF
        14.防御方式
            使用Referer防御是否一定可靠？
    SSRF
        15.绕过
            host 绕过
            ip进制绕过
            控制域名解析
            302跳转
            dns rebinding (ttl)
        16.有回显利用
            端口扫描
            攻击redis
        17.无回显利用
            dnslog
        18.防御
    文件上传
        19.绕过方式
        20.防御方式
    命令执行
        21.php
            绕过姿势
            shell_exec和exec的区别
        22.Java反序列化
            Shiro
## 启明星辰金融部
    1.常用的隧道都有哪些,reg是什么
    2.网络层的隧道都有哪些
    3.nmap都有哪些参数
    4.说说你理解的sql注入漏洞,XXE漏洞,SSRF漏洞,越权漏洞
    5.说说了解哪些框架漏洞
    6.shiro反序列化漏洞的原理
    7.struts2漏洞怎么测试
    8.怎么寻找域控
    9.黄金票据/白银票据介绍,有什么区别
    10.mimikatz符合什么条件可以抓到明文
    11.使用MSF进行后渗透,经常使用到哪些模块
    12.主机不出网的情况下怎么上线cs
    13.安卓的四大组件是什么
## 安恒
安恒的面试题
内网渗透，ntlm和lm有什么区别，linux权限维持（低权限），不出网机器怎么上线cs
 - ntlm加密过程:将明文转换为十六进制，经过Unicode转换后，再调用MD4加密
 - LM加密过程:
  1.将小写的[a-z]转换为大写 => a
  2.(a)转换为大写后将其hex编码 => b
  2.(b)hex编码后长度不为48bit，将其填充到112bit => c
  3.(c)将114bit编码的结果分成两组56bit => d
  4.(d)将两组56bit进行转换为二进制 => e
  (d)如果这两组不够56bit，转换为二进制后在左边填充足够的0到达56bit

  5.(e)将比特流按照7比特一组，分出8组，末尾加0 => f (2个8组的bit流)
  6.(f)将这8组bit流转换为16进制（每4位bit=1位十六进制）=> g
  7.(g)将两组的十六进制进行二进制的hex编码（返回由十六进制字符串 hexstr 表示的二进制数据（binascii.hex_a2b））=> h
  8.(h)将两组二进制hex编码的字符串，当作key对魔术字符串KGS!@#$%进行des编码，然后拼接两者得到LM hash
  
 不出网机器怎么上线cs:
  单机器只有web出网:http流量转发，毒刺
  两台机器(一台web出网，一台在内网):netsh防火墙转发流量到web出网的机器，smb beacon
 
 低权Linux维权:
  - webshell、内存马
  - vim配置
  - python配置
  - bash profile
  - 计划任务
  
白银票据和黄金票据的区别
 - 黄金票据:任意协议都可认证使用
 - 白银票据:指定协议才能使用

kerberos认证过程
kerberos认证某台机器:
 第一步:
 Client->Server Client向DC发出请求，请求包含:时间戳、client域用户的个人信息(Client info)、密钥的信息(KDC info)
 Client<-Server AS认证服务去AD中心查询client的域用户是否为合法用户，确认为合法用户后AS返回Client一张TGT（还有一个以client域用户密码加密的key这个密码也在TGT中（sesion key）），TGT上有Client info等信息，TGT由krbtgt hash加密
 
 第二步:
 Client->Server Client得到TGT后，再次向DC发起请求通过445端口使用session key加密自己域用户的信息和TGT
 Client<-Server DC得到TGT后会使用krbtgt hash解密TGT，得到session key和域用户info，然后将域用户info和数据库里面的比对，如果相同认证通过，DC返回session key加密过的server session key和ticket(服务票据) （这个票据用server hash加密，其中包含了server session key和域用户的信息）
 
 第三步:
 Client->Server Client拿到Server session server key和ticket发送给对应要验证的机器，对应的机器用自己的密码解密ticket，得到server session key和域用户信息，在用请求来的域用户信息和自己机器存放的信息进行比对，如果正确就认证通过
 
 
查询域命令
 net time /domain
 net user /domain
查询域控机器命令
 nltest /dclist:<domain>
 net group "Domain Controllers" /domain

常见的横向手法
 wmic、schtasks、powershell、psexec等
给你一个内网的环境怎么去渗透
 1.先确定网段大小
 2.扫描存活的机器
 3.判断windows和Linux的机器有多少台，是否有域
 4.针对对应的服务和web进行收集
 5.对服务展开针对性的漏洞利用（例如：redis未授权、MS17），和web进行攻击
 6.windows是否有域
 7.当前机器如果是windows拿到hash或明文的情况下尝试横向
 8.对Linux开了ssh的机器尝试爆破密码
还有就是只有一个webshell不出网怎么上线cs
 http流量转发
有没有接触过应急响应
 直接说有，然后瞎说即可
安了卡巴斯基的机器低权限怎么去横向/权限维持
 【没想到】
免杀
 改资源文件
 加壳
 修改重新编译
 特征码修改
 花指令
 shellcode加密
