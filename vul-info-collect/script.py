#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import re
from bs4 import BeautifulSoup
import math


class CveObject:
    cve_no = ''                     # 漏洞编号
    cve_url = ''                    # 漏洞cve url链接地址
    cve_nvd_url = ''                # 漏洞nvd url链接地址
    cve_description = ''            # 漏洞描述
    cve_create_time = ''            # 创建时间
    cve_modify_time = ''            # 修改时间
    cve_level = ''                  # 威胁等级
    cve_score = ''                  # 威胁评分
    cve_cna = ''                    # 漏洞分配的机构

    def show(self):
        """
        Show basic vul information
        :return: None
        """
        print('----------------------------------')
        print('编号：', self.cve_no)
        print('漏洞地址：', self.cve_url)
        print('漏洞描述：', self.cve_description[:10])
        print('创建时间:', self.cve_create_time)
        print('修改时间:', self.cve_modify_time)
        print('CNA:', self.cve_cna)
        print('漏洞等级：', self.cve_level)
        print('漏洞评分：', self.cve_score)
        print('\n\n')


# cve search url
search_url = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword='

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'
}

# 漏洞等级对应
level_dict = {
    'CRITICAL': '严重',
    'HIGH': '高',
    'MEDIUM': '中',
    'LOW': '低'
}

cve_obj_list = []           # cve obj-s fill with detailed information
cve_all = []                # cve no-s fetched from nvd

# for query information, need to provide : producer、software、banner
producer = 'oracle'
software = 'mysql'
banner = '5.7.21'


def fill_with_cve(cve, cve_obj):
    """
    Fetch detailed information by search cve to fill cve_obj that can be fetch from CVE
    :param cve: cve no
    :param cve_obj: cve object to fill
    :return: None
    """

    # construct cve url
    cve_url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='
    url = '{}{}'.format(cve_url, cve)
    # print(url)

    # fill cve obj with cve_no & cve_url
    cve_obj.cve_no = cve
    cve_obj.cve_url = url
    # print(cve_obj.cve_url)

    try:
        response = requests.get(url=url, timeout=15, headers=headers)
        soup = BeautifulSoup(response.text, features="lxml")

        # to get cve description or detail information
        result = soup.select('body > div#Page > div#CenterPane > div#GeneratedTable > table > tr')
        description = result[3].td.string
        cve_obj.cve_description = description

        # to get cve create time
        result = soup.select('body > div#Page > div#CenterPane > div#GeneratedTable > table > tr > td > b')
        time = result[1].string
        time = '{}-{}-{}'.format(time[:4], time[4:6], time[6:])
        # print('time...', time)

        # to get assgining cna
        result = soup.select('body > div#Page > div#CenterPane > div#GeneratedTable > table > tr')
        cna = result[8].td.string

        cve_obj.cve_create_time = time
        cve_obj.cve_cna = cna
    except:
        print('something bad happen when searching cve...')
    finally:
        pass


def fill_with_nvd(cve, cve_obj):
    """
    Fetch detailed information by search cve to fill cve_obj that can be fetch from NVD
    :param cve: cve no
    :param cve_obj: cve object to fill
    :return: None
    """
    nvd_url = 'https://nvd.nist.gov/vuln/detail/'
    url = '{}{}'.format(nvd_url, cve)
    cve_obj.cve_nvd_url = url
    # print(cve_obj.cve_nvd_url)

    try:
        response = requests.get(url, headers=headers, timeout=60)
        if response.status_code == 200:

            # to get modified time
            time = re.findall('"vuln-description-last-modified">(.*)?</span>', response.text)[0]
            month, day, year = time.split('/')
            time = '{}-{}-{}'.format(year, month, day)
            # print(time)
            cve_obj.cve_modify_time = time

            # to get vul score
            score = re.findall('"vuln-cvssv3-base-score">(.*)? </span>', response.text)
            if score.__len__() == 0:
                score = re.findall('"vuln-cvssv2-base-score">(.*)? </span>', response.text)
            # print(score[0])
            cve_obj.cve_score = score[0]

            # to get vul level
            severity = re.findall('"vuln-cvssv3-base-score-severity">(.*)?</span>', response.text)
            if severity.__len__() == 0:
                severity = re.findall('"vuln-cvssv2-base-score-severity">(.*)?</span>', response.text)
            # print(severity[0])
            cve_obj.cve_level = level_dict[severity[0]]
    except:
        print('something bad happen when searching nvd...')
    finally:
        pass
    pass


def fetch_all_cves():
    """
    Query NVD to get specific version of software vulnerabilities
    :return: None
    """
    # contruct query string
    if banner:
        keyword = '{}%3a{}'.format(software, banner)
    else:
        keyword = software
    url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&' \
          'cves=on&cpe_version=cpe%3a%2fa%3a{}%3a{}'.format(producer, keyword)
    print(url)

    # to get cve number
    try:
        response = requests.get(url, timeout=60, headers=headers)
        if response.status_code == 200:
            num = re.findall('"vuln-matching-records-count">(.*)?</strong>', response.text)[0]
            msg = 'There are {} cves with {} {}...'.format(num, software, banner)
            print(msg)
    except:
        pass

    # fetch all cve no
    start_index = index = 0
    while start_index < int(num):
        url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&' \
              'cves=on&cpe_version=cpe%3a%2fa%3a{}%3a{}&' \
              'startIndex={}'.format(producer, keyword, start_index)
        msg = 'processing page {}/{}...'.format(index+1, math.ceil(int(num) / 20))
        print(msg)
        index += 1
        start_index = index * 20
        try:
            response = requests.get(url, timeout=60, headers=headers)
            if response.status_code == 200:
                cves = re.findall('"vuln-detail-link-\d+">(.*)?</a>', response.text)
                cve_all.extend(cves)
        except:
            pass
    print('\n-------- CVEs ---------\n')
    for line in cve_all:
        print(line)
    print()


def fetch_vul_info():

    # get all cves
    fetch_all_cves()

    i = 0
    for cve in cve_all:
        i += 1
        cve_obj = CveObject()

        # if i == 4:
        #     break
        msg = '[{}/{}] Fetching {} ...'.format(i, cve_all.__len__(), cve)
        print(msg)
        # fill cve object with information from cve and nvd
        fill_with_cve(cve, cve_obj)
        fill_with_nvd(cve, cve_obj)
        cve_obj_list.append(cve_obj)
    pass


def save_cve_objs():
    """
    Save cve info to a file
    :return: None
    """
    for obj in cve_obj_list:
        cve_info = '{}|{}|{}|{}|{}|{}|{}|{}|{}\n'.format(obj.cve_no, obj.cve_url, obj.cve_nvd_url,
                                                       obj.cve_score, obj.cve_level, obj.cve_cna,
                                                       obj.cve_create_time, obj.cve_modify_time, obj.cve_description)
        with open('cve.txt', 'a+') as fw:
            fw.write(cve_info)


def write2html():
    """
    Write cve into to create a html file, this function is terriblely implemented, (^_^)
    :param keyword: software name
    :return: None
    """
    print('write data to html')
    html = ''
    header = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">\
<head>\
    <title>CVEs</title>\
    <meta content="text/html" charset="utf-8"></meta>\
    <link rel="stylesheet" type="text/css" href="list.css">\
</head>\
<body>\
<div id="div_title" align="center">\
    <div id="div_title_inner"><h1>CVEs for {} {} </h1></div>\
</div>\
<div id="div_title_occupy"></div>'

    header = header.format(software, banner)

    body = '<div id="div_main">\
    <div id="div_content"> \
        <div id="div_content_body"><h3>漏洞列表</h3>\
            <div id="uri_list_div">'

    vul_list = ''
    for obj in cve_obj_list:
        vul = '<a href="#{}">{}&nbsp;&nbsp;&nbsp;&nbsp;{}</a><br />'
        vul = vul.format(obj.cve_no, obj.cve_no, obj.cve_level)
        vul_list = '{}{}'.format(vul_list, vul)

    vul_left = '</div>\
        </div>\
    </div>\
    <div id="div_body">'

    body = '{}{}{}'.format(body, vul_list, vul_left)

    table = '<a name="vul-overview"></a><div id="div_get"> \
                <table class="uri_t" id="uri_table" border="1">\
                    <tr align="center">\
                        <td>等级</td>\
                        <td>严重</td>\
                        <td>高危</td>\
                        <td>中危</td>\
                        <td>低危</td>\
                    </tr>\
                    <tr align="center">\
                        <td>个数({})</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                    </tr>\
                </table>\
            </div>'

    a = b = c = d = e = 0
    for cve in cve_obj_list:
        if cve.cve_level == '严重':
            a += 1
        elif cve.cve_level == '高':
            b += 1
        elif cve.cve_level == '中':
            c += 1
        elif cve.cve_level == '低':
            d += 1
        else:
            e += 1

    table = table.format(cve_obj_list.__len__(), a, b, c, d)

    body = '{}{}'.format(body, table)

    for obj in cve_obj_list:
        cve_body = '<a name="{}"></a>\
            <div id="div_get">\
                <table class="uri_t" id="uri_table">\
                    <tr id="cve_no"><th>漏洞编号</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="vul_level"><th>威胁评分</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="cvss"><th>风险等级</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="date"><th>发现时间</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="date"><th>修改时间</th>\
                                <td>{}</td>\
                            </tr>\
                </table>\
                <p id="assign_cna">Assigning CNA</p>\
                <div id="example_div"><a id="cna">\
                    {}\
                    </a>\
                </div>\
                <p id="description">漏洞描述</p>\
                <div id="example_div"><a id="description">\
                    {}\
                    </a>\
                </div>\
                <p id="references">参考链接</p>\
                <div id="example_div"><a id="references">\
                    {}<br />{}\
                    </a>\
                </div>\
            </div>'

        cve_body = cve_body.format(obj.cve_no, obj.cve_no, obj.cve_score, obj.cve_level,
                                   obj.cve_create_time, obj.cve_modify_time, obj.cve_cna, obj.cve_description,
                                   obj.cve_url, obj.cve_nvd_url)

        body = '{}{}'.format(body, cve_body)

    footer = '</div>\
</div>\
<script>\
    function AjustContentHeight(){\
        var div_content = document.getElementById("div_content");\
        var div_body = document.getElementById("div_body")\
        var clientHeight = document.documentElement.clientHeight;\
        clientHeight -= 69;\
        div_content.style.height = clientHeight + "px";\
        div_body.style.height = clientHeight + "px";\
    }\
    window.onload=function(){AjustContentHeight();}\
    window.onresize=function(){AjustContentHeight();\
 }\
</script>\
</body>\
</html>'
    html = '{}{}{}'.format(header, body, footer)

    # write to cve html file for showing results
    with open('cve.html', 'w', encoding='utf-8') as fw:
        fw.write(html)


if __name__ == '__main__':
    # use '+' to connect keyword, eg. mysql+5.7.21
    fetch_vul_info()
    for obj in cve_obj_list:
        obj.show()
    write2html()
    save_cve_objs()
    pass
