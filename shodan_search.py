import optparse
import sys
import os
import shodan
import json
import datetime
import collections
from config import API_KEY, LIB_DIR
from search import Shodan_sort
from collections import namedtuple

Device_info = namedtuple('Device_info', ['outdir', 'device_type', 'brand'])


def initconnect():
    """
    init SHODAN_API_KEY
    :return: api
    """
    api = Shodan_sort(API_KEY)
    return api


def keyword_search(api, keyword, limit=100):
    """
    :param api: Use initconnect method generated api
    :param keyword: Want query keyword
    :param limit: Want query numbers
    :return: results
    """
    vulner_number = []
    results = collections.OrderedDict(api.search(keyword, limit=limit))
    return results


def input_result(keyword, results, outdir, brand, dev_type):
    #print(json.dumps(results['matches'][0], indent=4))
    filename = outdir + "{}_{}_result_{}.txt".format(brand, dev_type, datetime.datetime.now().strftime('%Y_%m_%d'))
    try:
        fileobj = open(filename,'w',encoding="utf-8")
        fileobj.write("数据条数:{}\n".format(results["total"]))
        for result in results["matches"]:
            fileobj.write(str(result)+"\n")
    except Exception as e:
        print("文件读取错误"+ e)
    finally:
        fileobj.close()
    print("文件{}写入完成".format(filename))


def get_Vulner(api, keyword, outdir, brand, dev_type):
    vulners = api.exploits.search(keyword)
    if vulners["total"] == 0:
        print("没有检索到exp")
    else:
        try:
            filename = outdir + "{}_{}_exp_{}.txt".format(brand,dev_type,datetime.datetime.now().strftime('%Y_%m_%d'))
            fileobj = open(filename,'w',encoding="utf-8")
            fileobj.write("检索到漏洞和exp的总条数:{}\n".format(vulners["total"]))
            for vulner in vulners["matches"]:
                fileobj.write(str(vulner)+"\n")
        except Exception as e:
            print("文件读取错误:"+e)
        finally:
            fileobj.close()
            print("文件{}写入完成".format(filename))


def get_file(api, filename):
    fileobj = open(filename)
    while True:
        line = fileobj.readline()
        if not line:
            break
        if line.startswith("#"):
            continue
        all_info = line.split(":::")
        if len(all_info) != 4:
            assert "Read file error"
        keyword = all_info[0].strip()
        out_dir = general_savelib(all_info[1].strip())
        dev_info = Device_info(out_dir, all_info[2].strip(), all_info[3].strip())
        results = keyword_search(api, keyword)

        input_result(keyword, results, dev_info.outdir, dev_info.device_type, dev_info.brand)
        get_Vulner(api, keyword, dev_info.outdir, dev_info.device_type, dev_info.brand)
    fileobj.close()


def general_savelib(outdir):
    """
    检查文件绝对路径是否存在，不存在则创建
    :param outdir:  文件的相对路径[camera, router, vpn]
    :return:        文件的绝对路径
    """
    if outdir.startswith('/'):
        dir = LIB_DIR + outdir
    else:
        dir = LIB_DIR + "/" + outdir

    abs_dir = os.getcwd() + "/" + dir + "/"
    if not os.path.exists(abs_dir):
        #新建目录
        os.makedirs(abs_dir)
    return abs_dir


if __name__ == "__main__":
    """
    example :
        python shodan_search -k "dir-850l" --outdir "router" --type "dir-850l" --brand "Dlink"
    """
    parser = optparse.OptionParser("usage:%prog wait")
    parser.add_option("-k", "--keyword",type='string',dest='keyword',help="Please input you want search keyword")
    parser.add_option("-l", "--limit", type="int",dest="limit", default=100)
    parser.add_option("-f", "--file", type="string",dest="file", help="Specified file")
    parser.add_option("--outdir", type="string", dest="outdir", help="Output type [camera, vpn, router]")
    parser.add_option("--type", type="string", dest="device_type", help="device model")
    parser.add_option("--brand", type="string", dest="brand", help="Name of manufacturer")

    (options,args) = parser.parse_args()
    api = initconnect()
    if options.outdir is None and options.file is None:
        parser.print_help()
        print("must need use --outdir or -f/--file")
        sys.exit(0)
    if options.keyword is None and options.file is None:
        parser.print_help()
        print("Keyword and file Cannot be None at the same time")
        sys.exit(0)
    elif options.file is None and options.keyword is not None:
        keyword = options.keyword
        limit = options.limit
        outdir = general_savelib(options.outdir)
        results = keyword_search(api,keyword,limit)

        input_result(keyword,results,outdir,options.brand,options.device_type)
        get_Vulner(api,keyword,outdir,options.brand,options.device_type)
    elif options.file is not None and options.keyword is None:
        filename = options.file
        get_file(api, filename)
