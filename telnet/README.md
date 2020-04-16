# TelnetClient
TelnetClient类，处理Telnet客户端相关，如最基本的登录和执行命令。

## Telnet登陆认证相关

```
auth = {
  "user_prompt": b'Username:',			# 输入用户名提示
  "password_prompt": b'Password:',		# 输入密码提示
  "enter": b'\r',						# 回车
  "remote_enter": b'\n\r',
}
```
有一点请注意，标准输入结尾是换行'\n'，也有一些是回车'\r'。

## Sample
仅供演示，脚本请自己改造。

```
# python3 telnet_brute.py
trying to login 172.16.176.120:2570 telnet service
try user:[admin], password:[admin]
try user:[aaa], password:[bbb]
try user:[], password:[]
登录成功
==> ver
 Version :PAS_SIPPROXY_6.0.0.3.0.190831, Compile Time: 16:18:41, Feb 25 2020
Return value: 1
SipPrxoy->
```
以上！