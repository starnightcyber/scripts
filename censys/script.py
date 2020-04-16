#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
import json
import requests
import time

API_URL = "https://www.censys.io/api/v1"
UID = "aa7c1f3a-b6ab-497d-9788-5e9e4898a655"
SECRET = "rSEvCfRQexNKXmpx940DQXWExWAFjkt1"
page = 1
PAGES = 2           # the pages you want to fetch


def getIp(query, page):
    '''
    Return ips and total amount when doing query
    '''
    iplist = []
    data = {
        "query": query,
        "page": page,
        "fields": ["ip", "protocols", "location.country"]
    }
    try:
        res = requests.post(API_URL + "/search/ipv4", data=json.dumps(data), auth=(UID, SECRET))

    except:
        pass
    try:
        results = res.json()
    except:
        pass
    if res.status_code != 200:
        print("error occurred: %s" % results["error"])
        sys.exit(1)
    # total query result
    # iplist.append("Total_count:%s" % (results["metadata"]["count"]))

    # add result in some specific form
    for result in results["results"]:
        for i in result["protocols"]:
            # iplist.append(result["ip"] + ':' + i + ' in ' + result["location.country"][0])
            iplist.append(result["ip"] + ':' + i)
    # return ips and total count
    return iplist, results["metadata"]["count"]


if __name__ == '__main__':

    query = input('please input query string : ')
    print('---', query, '---')
    ips, num = getIp(query=query, page=page)

    print("Total_count:%s" % num)

    dst = input('please input file name to save data (censys.txt default) : ')

    # 保存数据到文件
    if dst:
        dst = dst + '.txt'
    else:
        dst = 'censys.txt'

    # get result and save to file page by page
    with open(dst, 'a') as f:
        while page <= PAGES:
            print('page ：' + str(page))
            iplist, num = (getIp(query=query, page=page))
            page += 1

            for i in iplist:
                print i[:i.find('/')]

            for i in iplist:
                f.write(i[:i.find('/')] + '\n')
            time.sleep(3)
    print('Finished. data saved to file', dst)
