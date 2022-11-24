# 一个很简单的VMESS部署小教程

## 零.事前准备与需求

1. 一台VPS，最好是美国机房，有独立IPv4地址和root账户密码，操作系统为RHEL衍生发行版，比如CentOS Stream/Alma Linux/Rocky Linux(8-9都可以)
  
2. 一个顶级域名(比如example.com这种)
  
3. 一个CloudFlare账号(使用任意邮箱即可注册，不需要手机号/信用卡/实名验证等)
  
4. 足够的耐心
  

## 一.CloudFlare与DNS解析

1. 在注册或者登录到你的CloudFlare账户以后，
