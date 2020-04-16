#!/usr/bin/env python
# -*- coding:utf-8 -*-

import logging
import telnetlib
import time


# telnet登录认证相关
auth = {
  "user_prompt": b'Username:',			# 输入用户名提示
  "password_prompt": b'Password:',		# 输入密码提示
  "enter": b'\r',						# 回车
  "remote_enter": b'\n\r',
}


class TelnetClient(object):
	def __init__(self):
		self.tn = telnetlib.Telnet()		# Telnet client

	def login(self, ip, port, tel_dict):
		"""
		telnet 登录
		:param ip: 目标ip
		:param port: 目标端口
		:param tel_dict: 密码字典
		:return: 登录成功(True) or 登录失败(False)
		"""
		msg = 'trying to login {}:{} telnet service'.format(ip, port)
		print(msg)

		# telnet登录
		for username, password in tel_dict.items():

			# 创建一个telnet连接
			try:
				self.tn.open(ip, port)
			except:
				logging.warning('%s网络连接失败' % ip)
				return False, ''

			msg = 'try user:[{}], password:[{}]'.format(username, password)
			print(msg)

			# 登录尝试
			try:
				# 等待输入用户名提示user_prompt出现后，输入用户名
				self.tn.read_until(auth['user_prompt'], timeout=3)
				self.tn.write(username.encode('ascii') + auth['enter'])

				# 等待输入密码提示password_prompt出现后，输入密码
				self.tn.read_until(auth['password_prompt'], timeout=3)
				self.tn.write(password.encode('ascii') + auth['enter'])

				# 延时两秒再收取返回结果，给服务端足够响应时间
				time.sleep(2)

				# 获取登录结果, read_very_eager()获取到的是的是上次获取之后本次获取之前的所有输出
				command_result = self.tn.read_very_eager().decode('ascii')
				# print('===>', command_result)
				prompt, _ = command_result.split('->')
				# print('===>', prompt.strip())

				# 如果返回的结果中没有提示输入用户名，表示登录成功
				if auth['user_prompt'] not in command_result.encode('ascii'):
					print('登录成功')
					return True
				else:
					continue
			except:
				pass
		return False

	def execute_command(self, command):
		"""
        执行一些命令
        :param command: 要执行的命令
        :return: None
        """
		try:
			self.tn.write(command.encode('ascii') + auth['enter'])
			time.sleep(2)
			# 获取命令结果
			command_result = self.tn.read_very_eager().decode('ascii')
			print('==>', command_result)
		except:
			print('something went wrong...')
			pass

	# 退出telnet，保留
	def logout_host(self):
		self.tn.write(b"bye\r")

if __name__ == '__main__':

	# 参数
	ip = '172.16.176.120'
	port = '2570'
	tel_dict = {'admin': 'admin', 'aaa': 'bbb', '': ''}

	# 登陆
	tn = TelnetClient()
	tn.login(ip, port, tel_dict)

	# 执行命令
	command = 'ver'
	tn.execute_command(command)

	# 退出
	tn.logout_host()