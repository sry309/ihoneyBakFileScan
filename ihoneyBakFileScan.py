# 2018.04.20 www.T00ls.net
# __author__: ihoneysec
import requests
import logging
from binascii import b2a_hex
import multiprocessing
from argparse import ArgumentParser
from copy import deepcopy
from datetime import datetime

requests.packages.urllib3.disable_warnings()

logging.basicConfig(level=logging.WARNING, format="%(message)s")


def vlun(urltarget, df):
    try:
        r = requests.get(url=urltarget, headers=headers, timeout=timeout, allow_redirects=False, stream=True, verify=False)
        content = b2a_hex(r.raw.read(10)).decode()

        if r.status_code == 200:
            rarsize = int(r.headers.get('Content-Length')) // 1024 // 1024
            if content.startswith('526172') or content.startswith('504b03') or content.startswith('1f8b080000000000000b') or content.startswith('2d2d204d7953514c') or content.startswith(
                    '2d2d207068704d794164') or content.startswith('2f2a0a204e6176696361') or content.startswith('2d2d2041646d696e6572') or content.startswith(
                '2d2d202d2d2d2d2d2d2d') or content.startswith('2f2a0a4e617669636174'):
                #  or url.endswith('.sql') or url.endswith('.sql.bak') or url.endswith('.bak')
                logging.warning('[*] {}  size:{}M'.format(urltarget, rarsize))
                with open(df, 'a') as f:
                    try:
                        f.write(str(urltarget) + '  ' + 'size:' + str(rarsize) + 'M' + '\n')
                    except:
                        pass
            else:
                logging.warning('[ ] {}'.format(urltarget))
        else:
            logging.warning('[ ] {}'.format(urltarget))
    except Exception as e:
        pass


def urlcheck(target=None, ulist=None):
    if target is not None and ulist is not None:
        if target.startswith('http://') or target.startswith('https://'):
            if target.endswith('/'):
                ulist.append(target)
            else:
                ulist.append(target + '/')
        else:
            line = 'http://' + target
            if line.endswith('/'):
                ulist.append(line)
            else:
                ulist.append(line + '/')
        return ulist


def dispatcher(url_file=None, url=None, max_thread=1, dic=None):
    urllist = []

    if url_file is not None and url is None:
        with open(str(url_file)) as f:
            while True:
                line = str(f.readline()).strip()
                if line:
                    urllist = urlcheck(line, urllist)
                else:
                    break
    elif url is not None and url_file is None:
        url = str(url.strip())
        urllist = urlcheck(url, urllist)
    else:
        pass

    with open(datefile, 'w'):
        pass

    # MultiProcess
    pool = multiprocessing.Pool(max_thread)

    for u in urllist:
        ucp = u.strip('http://').strip('https://').strip('/')
        www1 = ucp.split('.')
        wwwlen = len(www1)
        wwwhost = ''
        for i in range(1, wwwlen):
            wwwhost += www1[i]

        current_info_dic = deepcopy(dic)  # deep copy
        suffixFormat = ['.rar', '.zip', '.gz', '.sql.gz', '.tar.gz', '.sql', ]
        domainDic = [ucp, ucp.replace('.', ''), wwwhost, ucp.split('.', 1)[-1], www1[0], www1[1]]

        for s in suffixFormat:
            for d in domainDic:
                current_info_dic.extend([d + s])

        for info in current_info_dic:
            url = str(u) + str(info)
            pool.apply_async(vlun, args=(url, datefile))

    pool.close()
    pool.join()


if __name__ == '__main__':
    usageexample = '\n       Example: python3.5 ihoneyBakFileScan -t 100 -f url.txt\n'
    usageexample += '                '
    usageexample += 'python3.5 ihoneyBakFileScan.py -u https://www.example.com/'

    parser = ArgumentParser(add_help=True, usage=usageexample, description='A Website Backup File Leak Scan Tool.')
    parser.add_argument('-f', '--url-file', dest="url_file", help="Example: url.txt")
    parser.add_argument('-t', '--thread', dest="max_threads", nargs='?', type=int, default=1, help="Max threads")
    parser.add_argument('-u', '--url', dest='url', nargs='?', type=str, help="Example: http://www.example.com/")
    parser.add_argument('-d', '--dict-file', dest='dict_file', nargs='?', help="Example: dict.txt")

    args = parser.parse_args()
    # Use the program default dictionary，Accurate scanning mode，Automatic dictionary generation based on domain name.
    info_dic = ['__zep__/js.zip', 'faisunzip.zip', ]

    datefile = datetime.now().strftime('%Y%m%d_%H-%M-%S.txt')

    headers = {'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36", }
    timeout = 5

    try:
        if args.dict_file:
            # Custom scan dictionary
            # This mode is not recommended for bulk scans. It is prone to false positives and can reduce program efficiency.
            custom_dict = list(set([i.replace("\n", "") for i in open(str(args.dict_file), "r").readlines()]))
            info_dic = info_dic.extend(custom_dict)
        if args.url:
            dispatcher(url=args.url, max_thread=args.max_threads, dic=info_dic)
        elif args.url_file:
            dispatcher(url_file=args.url_file, max_thread=args.max_threads, dic=info_dic)
        else:
            print("[!] Please specify a URL, or URL file name.")
    except Exception as e:
        pass
